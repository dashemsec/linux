#include "optee_caauth.h"

/*
 *  0 : not initialized
 *  1 : initialization SUCCESS
 * -1 : initialization FAILED
 */
static uint8_t is_optee_caauth_pta_enabled = 0;

static int match_version(struct tee_ioctl_version_data *a, const void *data)
{
	return 1;
}

static void uuid_to_octets(uint8_t d[TEE_IOCTL_UUID_LEN], const TEEC_UUID *s)
{
        d[0] = s->timeLow >> 24;
        d[1] = s->timeLow >> 16;
        d[2] = s->timeLow >> 8;
        d[3] = s->timeLow;
        d[4] = s->timeMid >> 8;
        d[5] = s->timeMid;
        d[6] = s->timeHiAndVersion >> 8;
        d[7] = s->timeHiAndVersion;
        memcpy(d + 8, s->clockSeqAndNode, sizeof(s->clockSeqAndNode));
}

static int optee_caauth_init(void)
{
	int retval = 0;
	uint32_t rc;
	struct tee_param param[4];
	struct tee_context *pteec = NULL;
	struct tee_ioctl_open_session_arg arg;
	TEEC_UUID uuid = TA_CAAUTH_UUID;
	const struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP,
	};

	pr_err("@@@@@@@@@@@@@@@@ Inside %s\n", __func__);
	pteec = tee_client_open_context(NULL, match_version, NULL, &v);
	if (IS_ERR(pteec)){
		retval = -EACCES;
		pr_err("ERROR: %s tee_client_open_context FAILED %x\n", __func__, IS_ERR(pteec));
		goto exit1;
	}

	memset(param, 0, sizeof(param));
	memset(&arg, 0, sizeof(arg));
	uuid_to_octets(arg.uuid, &uuid);
	arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	arg.num_params = 4;

	rc = tee_client_open_session(pteec, &arg, param);
	if (!rc && arg.ret) {		
		retval = -EACCES;
		pr_err("OPEN SESSION is failed with error %0x", arg.ret);
		goto exit1;
	}

	is_optee_caauth_pta_enabled = 1;

	tee_client_close_session(pteec, arg.session);
exit1:
	tee_client_close_context(pteec);
	return retval;
}

static int authenticate_caauth_with_optee(struct tee_context *ctx, struct tee_shm  *shm_img, int img_sz, struct tee_shm *shm_caauth, int caauth_sz)
{
	struct tee_param param[4];
	struct tee_ioctl_invoke_arg invoke_arg;
	TEEC_UUID uuid = TA_CAAUTH_UUID;
	struct tee_ioctl_open_session_arg arg;
	uint32_t rc;
	int retval = 0;

	memset(param, 0, sizeof(param));
	memset(&arg, 0, sizeof(arg));
	uuid_to_octets(arg.uuid, &uuid);
	arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	arg.num_params = 4;

	pr_err("@@@@@@@@@@@@@@@@ Inside %s\n", __func__);
	rc = tee_client_open_session(ctx, &arg, param);
	if (!rc && arg.ret)
	{		
		pr_err("OPEN SESSION is failed with error %0x", arg.ret);
		return -EACCES;
	}

	memset(&invoke_arg, 0, sizeof(invoke_arg));
	
	invoke_arg.func = 1;
	invoke_arg.session = arg.session;
	invoke_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	param[0].u.memref.shm = shm_img;
	param[0].u.memref.size = img_sz;
	param[0].u.memref.shm_offs = 0;
	
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	param[1].u.memref.shm = shm_caauth;
	param[1].u.memref.size = caauth_sz;
	param[1].u.memref.shm_offs = 0;

	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	pr_err("@@@@@@@@@@@@@@@@ Inside %s %d img_sz = %d caauth_sz = %d\n", __func__, __LINE__, img_sz, caauth_sz);
	rc = tee_client_invoke_func(ctx, &invoke_arg, param);
	if (rc || invoke_arg.ret)
	{
		pr_err("INVOKE COMMAND is failed with error %0x origin %d", invoke_arg.ret, invoke_arg.ret_origin);
		retval = -EACCES;
		goto exit1;
	}

exit1:
	tee_client_close_session(ctx, arg.session);
	return retval;
}

static int prepare_caauth_shm(struct file *elffile, char *img_buf, int img_sz, char *caauth_buf, int caauth_sz)
{
	int retval, sz, i;
	struct elfhdr *bin_elfhdr;
	loff_t off, caauthoff = 0;
	struct elf_shdr *bin_sechdrs = NULL;
	char *bin_secnames;

	/* FIRST COPY THE ELFHDR IN IMG DATA SHM */
	off = 0;
	retval = kernel_read(elffile, img_buf,
			     sizeof(struct elfhdr), &off);
	if (retval != sizeof(struct elfhdr)) {
		pr_err("ERROR: Failed to read ELF headers retval = %d\n", retval);
		retval = -EIO;
		goto exit;
	}

	bin_elfhdr = (struct elfhdr *) img_buf;

	/* ALLOCATE & COPY THE SECTION HEADERS IN DYN MEM */
	sz = sizeof(struct elf_shdr) * bin_elfhdr->e_shnum;
	bin_sechdrs = kmalloc(sz, GFP_KERNEL);
	if (!bin_sechdrs) {
		retval = -ENOMEM;
		pr_err("ERROR: No memory for section header\n");
		goto exit;
	}

	off = bin_elfhdr->e_shoff;
	retval = kernel_read(elffile, (char *)bin_sechdrs, sz, &off);
	if (retval != sz) {
		pr_err("ERROR: Failed to read Section headers\n");
		retval = -EIO;
		goto error2;
	}

	/* ALLOCATE & COPY THE SECTION NAMES IN DYN MEM */
	bin_secnames = kmalloc(bin_sechdrs[bin_elfhdr->e_shstrndx].sh_size, GFP_KERNEL);
	if (!bin_secnames) {
		retval = -ENOMEM;
		pr_err("ERROR: No memory for section names\n");
		goto error2;
	}

	off = bin_sechdrs[bin_elfhdr->e_shstrndx].sh_offset;

	retval = kernel_read(elffile,
			(char *)bin_secnames,
			bin_sechdrs[bin_elfhdr->e_shstrndx].sh_size, &off);
	if (retval != bin_sechdrs[bin_elfhdr->e_shstrndx].sh_size) {
		pr_err("ERROR: Failed to read Section Names\n");
		retval = -EIO;
		goto error3;
	}

	/* FIND THE CAAUTH OFF */
	for (i = 1; i < bin_elfhdr->e_shnum; i++) {
		if (!strcmp(bin_secnames + bin_sechdrs[i].sh_name, AUTH_SEC_NAME)) {
			caauthoff = bin_sechdrs[i].sh_offset;
		}
	}

	if (caauthoff == 0) {
		retval = -EIO;
		goto error3;
	}

	/* COPY THE CONTENT FROM PROGRAM HEADER START TILL CAAUTH START IN IMG DATA SHM */
	off = bin_elfhdr->e_phoff;
	sz = caauthoff - off;
	retval = kernel_read(elffile, &img_buf[off],
			     sz, &off);
	if (retval != sz) {
		pr_err("ERROR: Failed to read data after elfhdr retval = %d\n", retval);
		retval = -EIO;
		goto error3;
	}

	/* COPY THE CAAUTH DATA IN CAAUTH SHM */
	off = caauthoff;
	retval = kernel_read(elffile, caauth_buf,
			     caauth_sz, &off);
	if (retval != caauth_sz) {
		pr_err("ERROR: Failed to read caauth data retval = %d\n", retval);
		retval = -EIO;
		goto error3;
	}

	/* REMOVE THE CAAUTH SECTION FROM SECTION HEADER & SHSTRTAB STRING */
	off = caauthoff;
	sz = bin_sechdrs[bin_elfhdr->e_shstrndx].sh_size - (strlen(AUTH_SEC_NAME) + 1);
	bin_sechdrs[bin_elfhdr->e_shstrndx].sh_size = sz; /* modify the size of shstrtab section */
	memcpy(&img_buf[off], bin_secnames, sz); /* copy the modified shstrtab section */

	off += sz + 1; /* new offset for section headers */
	i = bin_elfhdr->e_shstrndx;
	bin_sechdrs[i].sh_offset = caauthoff;
	memcpy(&bin_sechdrs[i-1], &bin_sechdrs[i], sizeof(struct elf_shdr));

	/* MODIFY THE ELF HEADER */
	bin_elfhdr->e_shnum -= 1;
	bin_elfhdr->e_shstrndx -= 1;
	bin_elfhdr->e_shoff = off;

	/* AT LAST WRITE THE UPDATED SECTION HEADERS */
	sz = sizeof(struct elf_shdr) * bin_elfhdr->e_shnum;
	memcpy(&img_buf[bin_elfhdr->e_shoff], bin_sechdrs, sz);


error3:
	kfree(bin_secnames);
error2:
	kfree(bin_sechdrs);
	
exit:
	return retval;
}

/*
 * find_sig_section_get_imgsz() - find caauth section, and if found, return the original
 *				  image size without the caauth, else return negative error
 *				  code.
 */
static unsigned long find_caauthdata_size(struct file *elf_file)
{
	struct elfhdr *local_elf = NULL;
	struct elf_shdr *sechdrs = NULL;
	int size;
	int retval;
	int i = 0;
	char *strtab;
	loff_t off;

	local_elf = kmalloc(sizeof(struct elfhdr), GFP_KERNEL);
	if (!local_elf) {
		retval = -ENOMEM;
		pr_err("ERROR: no memory ELF header\n");
		goto exit1;
	}

	off = 0;
	 /*Read fresh ELF headers*/
	retval = kernel_read(elf_file, local_elf,
			     sizeof(struct elfhdr), &off);
	if (retval != sizeof(struct elfhdr)) {
		pr_err("ERROR: Failed to read ELF headers retval = %d\n", retval);
		retval = -EIO;
		goto exit2;
	}

	/*Section header size.*/
	size = sizeof(struct elf_shdr) * local_elf->e_shnum;

	sechdrs = kmalloc(size, GFP_KERNEL);
	if (!sechdrs) {
		retval = -ENOMEM;
		pr_err("ERROR: No memory for section header\n");
		goto exit2;
	}

	off = local_elf->e_shoff;
	 /*Read in the Section headers*/
	retval = kernel_read(elf_file, (char *)sechdrs, size, &off);
	if (retval != size) {
		pr_err("ERROR: Failed to read Section headers\n");
		retval = -EIO;
		goto exit3;
	}

	/* Allocate for strtab */
	strtab = kmalloc(sechdrs[local_elf->e_shstrndx].sh_size, GFP_KERNEL);
	if (!strtab) {
		retval = -ENOMEM;
		pr_err("ERROR: No memory for section names\n");
		goto exit3;
	}

	/* Read in the Section Names */
	off = sechdrs[local_elf->e_shstrndx].sh_offset;
	retval = kernel_read(elf_file,
			(char *)strtab,
			sechdrs[local_elf->e_shstrndx].sh_size, &off);
	if (retval != sechdrs[local_elf->e_shstrndx].sh_size) {
		pr_err("ERROR: Failed to read Section Names\n");
		retval = -EIO;
		goto exit4;
	}

	retval = -EIO;
	/* Find the caauth section */
	for (i = 1; i < local_elf->e_shnum; i++) {
		if (!strcmp(strtab + sechdrs[i].sh_name, AUTH_SEC_NAME)) {
			retval = sechdrs[i].sh_size;
			break;
		}
	}

exit4:
	kfree(strtab);
exit3:
	kfree(sechdrs);
exit2:
	kfree(local_elf);
exit1:
	return retval;
}

int optee_find_and_validate_casignature(struct linux_binprm *bprm)
{
	int retval = 0;
	int img_size, caauth_sz;
	struct tee_shm *shm_img = NULL, *shm_caauth = NULL;
	void *va_img, *va_caauth;
	loff_t elfoff;
	struct tee_context *pteec = NULL;
	const struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP,
	};

	/* Flag check first */
	if (0 == is_optee_caauth_pta_enabled) {
		if (!optee_caauth_init()) {
			is_optee_caauth_pta_enabled = 1;
		} else {
			is_optee_caauth_pta_enabled = -1;
			return -EACCES;
		}
	}

	/* look for the .caauth section in ELF */
	caauth_sz = find_caauthdata_size(bprm->file);

	if (caauth_sz < 0) {
		/*pr_err("ERROR: No .caauth section\n");*/
		retval = -ENOENT;
		bprm->cred->caauth_flag |= CAVERIFY_FLAG_CAAUTH_NOT_FOUND;
		goto exit1;
	}

	bprm->cred->caauth_flag |= CAVERIFY_FLAG_CAAUTH_FOUND;

	elfoff = vfs_llseek(bprm->file, 0, SEEK_END);
	pr_err("@@@ elf file size = %d, caauthsize = %d, elf_shdr size = %d, %s sz = %d", (int)elfoff, (int)caauth_sz, sizeof(struct elf_shdr), AUTH_SEC_NAME, sizeof(AUTH_SEC_NAME));

	img_size = elfoff - (sizeof(struct elf_shdr) + sizeof(AUTH_SEC_NAME) + caauth_sz);

	pr_err("@@@@@ img_size = %d caauthdata = %d\n", img_size, caauth_sz);

	pteec = tee_client_open_context(NULL, match_version, NULL, &v);
	if (IS_ERR(pteec)){
		retval = -EACCES;
		pr_err("ERROR: %s tee_client_open_context FAILED %x\n", __func__, IS_ERR(pteec));
		goto exit1;
	}

	/* Prepare shared memory for image data */
	shm_img = tee_shm_alloc(pteec, img_size, TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
	if (IS_ERR(shm_img)) {
		retval = -EACCES;
		pr_err("ERROR: %s No TEE Shared Memory for IMG data\n", __func__);
		goto exit2;
	}

	va_img = tee_shm_get_va(shm_img, 0);
	if (IS_ERR(va_img)) {
		retval = -EACCES;
		pr_err("ERROR: %s MMAP Shared Memory Failed for IMG data\n", __func__);
		goto exit3;
	}

	/* Prepare shared memory for caauth data*/
	shm_caauth = tee_shm_alloc(pteec, caauth_sz, TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
	if (IS_ERR(shm_caauth)) {
		retval = -EACCES;
		pr_err("ERROR: %s No TEE Shared Memory for IMG data\n", __func__);
		goto exit3;
	}

	va_caauth = tee_shm_get_va(shm_caauth, 0);
	if (IS_ERR(va_caauth)) {
		retval = -EACCES;
		pr_err("ERROR: %s MMAP Shared Memory Failed for IMG data\n", __func__);
		goto exit4;
	}

	bprm->cred->caauth_flag |= CAVERIFY_FLAG_AUTH_FAILED;
	if (!prepare_caauth_shm(bprm->file, (char *)va_img, img_size, (char *)va_caauth, caauth_sz)) {
		retval = -EACCES;
		goto exit4;
	}

	if (!authenticate_caauth_with_optee(pteec, shm_img, img_size, shm_caauth, caauth_sz))
		bprm->cred->caauth_flag |= CAVERIFY_FLAG_AUTH_SUCCESS;

exit4:
	tee_shm_free(shm_caauth);
exit3:
	tee_shm_free(shm_img);
exit2:
	tee_client_close_context(pteec);
exit1:
	bprm->cred->caauth_flag |= CAVERIFY_FLAG_VALIDATION_DONE;
	return retval;
}

int optee_check_dev_permission(uint16_t caauth_flag) {

	if (1 != is_optee_caauth_pta_enabled)
		return -EACCES;

	if (caauth_flag & CAVERIFY_FLAG_VALIDATION_DONE) {

		/* NOT ALLOW IF CAAUTH SECTION IS NOT FOUND IN ELF */
		if (!(caauth_flag & CAVERIFY_FLAG_CAAUTH_FOUND)) {
			pr_err("NOT ALLOWED UNSIGNED CA...");
			return -EACCES;
		} else {
			/* Check if AUTHENTICATION is OKAY */
			if (!(caauth_flag & CAVERIFY_FLAG_AUTH_SUCCESS)) {
				pr_err("CA AUTHENTICATION ERROR...");
				return -EACCES;
			}
		}

		pr_info("CA AUTHENTICATION SUCCESS !!!");
	} else {
		pr_err("CA VALIDATION NOT DONE ERROR !!!");
		return -EACCES;
	}

	return 0;
}
