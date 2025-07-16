// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Userspace Process Configuration
 */

#include <string.h>
#include <stdbool.h>
#include <percpu.h>
#include <sched.h>
#include <mem.h>
#include <list.h>
#include <device.h>
#include <kmalloc.h>
#include <sbrk.h>
#include <strmisc.h>
#include <file.h>
#include <thread.h>
#include <trace.h>
#include <errno.h>

#include <property.h>

/* default public devices permitted for all TAs */
#define DEV_PUB_ACL "/dev/null,/dev/urandom,/dev/uart0"

static LIST_HEAD(pconfigs);
static DECLARE_MUTEX(pconf_mtx);

struct process_config *process_config_of_uuid(const TEE_UUID *uuid)
{
	struct process_config *c = NULL, *ret = NULL;

	if (!uuid)
		return NULL;

	mutex_lock(&pconf_mtx);
	list_for_each_entry(c, &pconfigs, node) {
		if (memcmp(uuid, &c->uuid,
			sizeof(TEE_UUID)) == 0) {
			ret = c;
			break;
		}
	}
	mutex_unlock(&pconf_mtx);

	return ret;
}

struct process_config *process_config_of(const char *name)
{
	struct process_config *ret = NULL;
	struct process_config *c = NULL;
	bool is_path = false;

	if (!name)
		return NULL;

	is_path = !!strchr(name, '/');

	mutex_lock(&pconf_mtx);
	list_for_each_entry(c, &pconfigs, node) {
		if (strcmp(name, is_path ? c->path : c->name) == 0) {
			ret = c;
			break;
		}

		/* Backward-compatibility: match by name even if caller passed a path-like string. */
		if (is_path && strcmp(name, c->name) == 0) {
			ret = c;
			break;
		}
	}
	mutex_unlock(&pconf_mtx);

	return ret;
}

void process_handle_fs(const char *mnt)
{
	struct process_config *c = NULL;
	unsigned long l = 0;
	char path[FS_PATH_MAX];

	mutex_lock(&pconf_mtx);

	list_for_each_entry(c, &pconfigs, node) {
		if (!c->privilege) {
			l = snprintf(path, sizeof(path), "%s/%s", mnt, c->name);
			if (l >= sizeof(path))
				continue;
			sys_mkdir(path, 0700);
		}
	}

	mutex_unlock(&pconf_mtx);
}

static char *strstr_of(char *buf, const char *e)
{
	char *pos = NULL;
	size_t elen = 0;

	if (!buf || !e)
		return NULL;

	elen = strlen(e);
	pos = buf;
	while ((pos = strstr(pos, e)) != NULL) {
		/* check if it is a whole word match */
		if ((pos == buf || pos[-1] == ' ' || pos[-1] == '\t' ||
			pos[-1] == '\n' || pos[-1] == '\r') &&
			(pos[elen] == '=' || pos[elen] == ' ' || pos[elen] == '\t')) {
			break;
		}
		pos++;
	}

	if (!pos)
		return NULL;

	pos = strchr(pos, '=');
	if (!pos)
		return NULL;

	pos++;
	/* skip whitespace after '=' */
	while (*pos == ' ' || *pos == '\t')
		pos++;

	if (*pos == '"') {
		/* key="value" format */
		pos++;
		return pos;
	} else {
		/* key=value format */
		return pos;
	}
}

static int strlen_of(char *buf, const char *e, const char *eoc)
{
	char *pos = NULL;
	int len = 0;
	size_t elen = 0;

	if (!buf || !e)
		return 0;

	elen = strlen(e);
	pos = buf;
	while ((pos = strstr(pos, e)) != NULL) {
		/* check if it is a whole word match */
		if ((pos == buf || pos[-1] == ' ' || pos[-1] == '\t' ||
			pos[-1] == '\n' || pos[-1] == '\r') &&
			(pos[elen] == '=' || pos[elen] == ' ' || pos[elen] == '\t')) {
			break;
		}
		pos++;
	}

	if (!pos)
		return 0;

	pos = strchr(pos, '=');
	if (!pos)
		return 0;

	pos++;
	/* skip whitespace after '=' */
	while ((pos < eoc) && (*pos == ' ' || *pos == '\t'))
		pos++;

	if (pos < eoc && *pos == '"') {
		/* key="value" format */
		pos++;
		while ((pos + len < eoc) && (*(pos + len) != '"')) {
			if (*(pos + len) == '=')
				return 0;
			len++;
		}
		return len;
	} else {
		/* key=value format */
		while ((pos + len < eoc) && (*(pos + len) != '\n') && (*(pos + len) != '\r')) {
			if (*(pos + len) == ';')
				break;
			if (*(pos + len) == '=')
				return 0;
			len++;
		}
		/* trim trailing whitespace */
		while (len > 0 && (pos[len-1] == ' ' || pos[len-1] == '\t'))
			len--;
		return len;
	}
}

static char *strncpy_config(char *dest, const char *src, size_t n)
{
	if (n != 0) {
		char *d = dest;
		const char *s = src;

		do {
			*d = *s++;
			if (*d == 0)
				break;
			if ((*d == ' ') ||
				(*d == '\t') ||
				(*d == '\r') ||
				(*d == '\n')) {
				*d = 0;
				continue;
			}
			d++;
		} while (--n != 0);
		*d = 0;
	}
	return dest;
}

static int uuid2val(const char *c, size_t size, TEE_UUID *uuid)
{
	int i = 0, ret = false;
	char *temptr_strtok = NULL;
	char *c_bak = NULL;
	short clock_seq_hilow = 0;
	char *split_c = "-";
	char tmp[65];

	if (size >= sizeof(tmp))
		return false;

	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, c, size);
	temptr_strtok = strtok_r(tmp, split_c, &c_bak);
	if (!temptr_strtok)
		goto out;
	uuid->timeLow = strtoul(temptr_strtok, NULL, 16);

	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	if (!temptr_strtok)
		goto out;
	uuid->timeMid = strtoul(temptr_strtok, NULL, 16);

	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	if (!temptr_strtok)
		goto out;
	uuid->timeHiAndVersion = strtoul(temptr_strtok, NULL, 16);

	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	if (!temptr_strtok)
		goto out;
	clock_seq_hilow = strtoul(temptr_strtok, NULL, 16);
	uuid->clockSeqAndNode[0] = clock_seq_hilow >> 8;
	uuid->clockSeqAndNode[1] = clock_seq_hilow;

	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	while (temptr_strtok && *temptr_strtok && (i < 6)) {
		tmp[0] = temptr_strtok[0];
		tmp[1] = temptr_strtok[1];
		tmp[2] = 0;
		uuid->clockSeqAndNode[i + 2] = strtoul(tmp, NULL, 16);
		temptr_strtok += 2;
		i++;
	}

	if (uuid->timeLow == 0 || uuid->timeMid == 0 || clock_seq_hilow == 0)
		goto out;

	ret = true;

out:
	if (!ret)
		EMSG("invalid uuid %s\n", tmp);
	return ret;
}

static int get_uuid_from_config(char *c, int size, TEE_UUID *uuid)
{
	int len = strlen_of(c, "uuid", c + size);

	if (len == 0 || len >= 64) {
		EMSG("no uuid ??\n");
		return false;
	}

	return uuid2val(strstr_of(c, "uuid"), len, uuid);
}

static int process_config_validate(char *c, int size, TEE_UUID *uuid)
{
	int ret = false;
	const char *eoc = c + size;

	if (get_uuid_from_config(c, size, uuid) == 0)
		goto out;

	/* Must have 'name' */
	if (strlen_of(c, "name", eoc) == 0) {
		EMSG("invalid name\n");
		goto out;
	}

	/* TA must have 'path' */
	if (strlen_of(c, "path", eoc) == 0) {
		EMSG("invalid path info\n");
		goto out;
	}

	if (strlen_of(c, "stack_size", eoc) == 0) {
		EMSG("invalid stack_size\n");
		goto out;
	}

	if (strlen_of(c, "heap_size", eoc) == 0) {
		EMSG("invalid heap_size\n");
		goto out;
	}

	if (strlen_of(c, "single_instance", eoc) != 1) {
		EMSG("invalid single_instance\n");
		goto out;
	}

	if (strlen_of(c, "dev_access", eoc) < 6) {
		EMSG("invalid dev_access\n");
		goto out;
	}

	ret = true;

out:
	return ret;
}

static int process_duplicated(const char *name, TEE_UUID *uuid)
{
	struct process_config *c = NULL, *ret = NULL;

	mutex_lock(&pconf_mtx);

	list_for_each_entry(c, &pconfigs, node) {
		if (memcmp(uuid, &c->uuid, sizeof(TEE_UUID)) == 0 ||
			strcmp(name, c->name) == 0) {
			ret = c;
			break;
		}
	}

	mutex_unlock(&pconf_mtx);

	return !!ret;
}

static const char *propnames_ta[PROP_NR_TA] = {
	GPD_TA_APPID,
	GPD_TA_SINGLEINSTANCE,
	GPD_TA_MULTISESSION,
	GPD_TA_INSTANCEKEEPALIVE,
	GPD_TA_DATASIZE,
	GPD_TA_STACKSIZE,
	GPD_TA_VERSION,
	GPD_TA_DESCRIPTION,
	GPD_TA_ENDIAN,
};

static const char *propnames_client[PROP_NR_CLIENT] = {
	GPD_CLIENT_IDENTITY,
	GPD_CLIENT_ENDIAN,
};

static int get_additional_ta_property(struct process_config *c,
		const char *name, struct property *p)
{
	char *str = NULL, chr;
	char type[PROP_SIZE_MAX];
	char val[PROP_SIZE_MAX];
	uint32_t data = 0, i = 0, vallen = 0;
	uint64_t data64 = 0;
	TEE_Identity id;

	if (!c->additionalprops || c->nr_additionalprops == 0)
		return -ENOENT;

	str = strstr(c->additionalprops, name);
	if (!str)
		return -ENOENT;

	while (*str != ':' && *str != 0)
		str++;
	if (*str == 0)
		return -ENOENT;
	str++;

	while ((chr = *str++) != ':') {
		if (chr == 0)
			return -ENOENT;
		if (i < sizeof(type) - 1)
			type[i++] = chr;
	}
	type[i] = 0;

	i = 0;
	while ((chr = *str++) != '>') {
		if (chr == 0)
			return -ENOENT;
		if (i < sizeof(val) - 1)
			val[i++] = chr;
	}
	val[i] = 0;
	vallen = i;

	if (strcmp(type, "boolean") == 0) {
		p->type = PROP_TYPE_BOOLEAN;
		data = strtoul(val, NULL, 0);
		memcpy(p->data, &data, sizeof(bool));
	} else if (strcmp(type, "string") == 0) {
		p->type = PROP_TYPE_STRING;
		strlcpy(p->data, val, PROP_SIZE_MAX);
	} else if (strcmp(type, "u32") == 0) {
		p->type = PROP_TYPE_U32;
		data = strtoul(val, NULL, 0);
		memcpy(p->data, &data, sizeof(uint32_t));
	} else if (strcmp(type, "uuid") == 0) {
		p->type = PROP_TYPE_UUID;
		uuid2val(val, vallen, (TEE_UUID *)p->data);
	} else if (strcmp(type, "binary") == 0) {
		p->type = PROP_TYPE_BINARY;
		strlcpy(p->data, val, PROP_SIZE_MAX);
	} else if (strcmp(type, "identity") == 0) {
		i = 0;
		while (i < vallen && val[i] != ':')
			i++;

		if (i < vallen) {
			val[i++] = 0;
			p->type = PROP_TYPE_IDENTITY;
			id.login = strtoul(val, NULL, 16);
			uuid2val(&val[i], vallen - i, &id.uuid);
			memcpy(p->data, &id, sizeof(id));
		}
	} else if (strcmp(type, "u64") == 0) {
		p->type = PROP_TYPE_U64;
		data64 = strtoull(val, NULL, 0);
		memcpy(p->data, &data64, sizeof(uint64_t));
	}

	strlcpy(p->name, name, PROP_SIZE_MAX);

	return 0;
}

static int get_ta_property(struct process_config *c, const char *name, struct property *p)
{
	uint32_t data = 0;

	/* Fixed Process(TA) PropSets */
	if (strcmp(name, GPD_TA_APPID) == 0) {
		p->type = PROP_TYPE_UUID;
		strlcpy(p->name, GPD_TA_APPID, PROP_SIZE_MAX);
		memcpy(p->data, &c->uuid, sizeof(TEE_UUID));
	} else if (strcmp(name, GPD_TA_SINGLEINSTANCE) == 0) {
		p->type = PROP_TYPE_BOOLEAN;
		strlcpy(p->name, GPD_TA_SINGLEINSTANCE, PROP_SIZE_MAX);
		memcpy(p->data, &c->single_instance, sizeof(bool));
	} else if (strcmp(name, GPD_TA_MULTISESSION) == 0) {
		p->type = PROP_TYPE_BOOLEAN;
		strlcpy(p->name, GPD_TA_MULTISESSION, PROP_SIZE_MAX);
		memcpy(p->data, &c->multi_session, sizeof(bool));
	} else if (strcmp(name, GPD_TA_INSTANCEKEEPALIVE) == 0) {
		p->type = PROP_TYPE_BOOLEAN;
		strlcpy(p->name, GPD_TA_INSTANCEKEEPALIVE, PROP_SIZE_MAX);
		memcpy(p->data, &c->inst_keepalive, sizeof(bool));
	} else if (strcmp(name, GPD_TA_DATASIZE) == 0) {
		p->type = PROP_TYPE_U32;
		strlcpy(p->name, GPD_TA_DATASIZE, PROP_SIZE_MAX);
		memcpy(p->data, &c->heap_size, sizeof(uint32_t));
	} else if (strcmp(name, GPD_TA_STACKSIZE) == 0) {
		p->type = PROP_TYPE_U32;
		strlcpy(p->name, GPD_TA_STACKSIZE, PROP_SIZE_MAX);
		memcpy(p->data, &c->ustack_size, sizeof(uint32_t));
	} else if (strcmp(name, GPD_TA_VERSION) == 0) {
		p->type = PROP_TYPE_STRING;
		strlcpy(p->name, GPD_TA_VERSION, PROP_SIZE_MAX);
		strlcpy(p->data, c->version, min(sizeof(c->version), sizeof(p->data)));
	} else if (strcmp(name, GPD_TA_DESCRIPTION) == 0) {
		p->type = PROP_TYPE_STRING;
		strlcpy(p->name, GPD_TA_DESCRIPTION, PROP_SIZE_MAX);
		strlcpy(p->data, c->description, min(sizeof(c->description), sizeof(p->data)));
	} else if (strcmp(name, GPD_TA_ENDIAN) == 0) {
		p->type = PROP_TYPE_U32;
		strlcpy(p->name, GPD_TA_ENDIAN, PROP_SIZE_MAX);
		memcpy(p->data, &data, sizeof(uint32_t));
	} else {
		/* Additional Process(TA) PropSets */
		return get_additional_ta_property(c, name, p);
	}

	return 0;
}

int process_get_property(struct process_config *c,
	unsigned long hdl, const void *nameoridx, struct property *p)
{
	if (hdl == PROP_HANDLES_TA) {
		/* it's an idx - additional idx not included ? */
		if ((unsigned long)nameoridx < PROP_NR_TA)
			nameoridx = propnames_ta[(unsigned long)nameoridx];
		if (IS_ERR_PTR((void *)nameoridx))
			return -ENOENT;

		return get_ta_property(c, nameoridx, p);
	} else if (hdl == PROP_HANDLES_CLIENT) {
		TEE_Identity id;
		uint32_t data = false; /* always little endian */

		/* it's an idx - additional idx not included ? */
		if ((unsigned long)nameoridx < PROP_NR_CLIENT)
			nameoridx = propnames_client[(unsigned long)nameoridx];
		if (IS_ERR_PTR((void *)nameoridx))
			return -ENOENT;

		if (strcmp(nameoridx, GPD_CLIENT_ENDIAN) == 0) {
			p->type = PROP_TYPE_U32;
			strlcpy(p->name, GPD_CLIENT_ENDIAN, PROP_SIZE_MAX);
			memcpy(p->data, &data, sizeof(uint32_t));
		} else if (strcmp(nameoridx, GPD_CLIENT_IDENTITY) == 0) {
			id.login = TEE_LOGIN_TRUSTED_APP;
			memcpy(&id.uuid, &c->uuid, sizeof(TEE_UUID));
			p->type = PROP_TYPE_IDENTITY;
			strlcpy(p->name, GPD_CLIENT_IDENTITY, PROP_SIZE_MAX);
			memcpy(p->data, &id, sizeof(TEE_Identity));
		} else {
			return -ENOENT;
		}
	}

	return 0;
}

int process_config_set(char *config, size_t size, bool privilege)
{
	int e_size = 0, name_l = 0, pub_len = 0, sep = 0;
	const char *eoc = config + size;
	struct process_config *c = NULL;
	char *str = NULL;
	TEE_UUID uuid;

	if (process_config_validate(config, size, &uuid) == 0)
		return -EINVAL;

	c = kzalloc(sizeof(struct process_config));
	if (!c)
		return -ENOMEM;

	memcpy(&c->uuid, &uuid, sizeof(uuid));

	e_size = strlen_of(config, "name", eoc);
	if (e_size <= 0 || e_size >= PROCESS_NAME_LEN) {
		EMSG("error name len - %s\n", strstr_of(config, "name"));
		kfree(c);
		return -EINVAL;
	}
	strncpy_trim(c->name, strstr_of(config, "name"), e_size);

	e_size = strlen_of(config, "path", eoc);
	if (e_size <= 0 || e_size >= PROCESS_PATH_LEN) {
		EMSG("error path len - %s\n", strstr_of(config, "name"));
		kfree(c);
		return -EINVAL;
	}
	strncpy_trim(c->path, strstr_of(config, "path"), e_size);

	str = strstr_of(config, "single_instance");
	if (str)
		c->single_instance = strtoul(str, NULL, 0);
	str = strstr_of(config, "multi_session");
	if (str)
		c->multi_session = strtoul(str, NULL, 0);
	str = strstr_of(config, "inst_keepalive");
	if (str)
		c->inst_keepalive = strtoul(str, NULL, 0);
	str = strstr_of(config, "heap_size");
	if (str)
		c->heap_size = strtoul(str, NULL, 0);
	str = strstr_of(config, "stack_size");
	if (str)
		c->ustack_size = strtoul(str, NULL, 0);
	if (privilege) {
		str = strstr_of(config, "privilege");
		if (str)
			c->privilege = strtoul(str, NULL, 0);
	}

	e_size = strlen_of(config, "version", eoc);
	if ((e_size > 0) && (e_size < PROCESS_VER_LEN))
		strncpy_trim(c->version, strstr_of(config, "version"), e_size);

	e_size = strlen_of(config, "description", eoc);
	if ((e_size > 0) && (e_size < PROP_SIZE_MAX))
		strncpy_trim(c->description, strstr_of(config, "description"), e_size);

	if (process_duplicated(c->name, &c->uuid)) {
		EMSG("duplicated TA @ %s\n", c->name);
		kfree(c);
		return -EEXIST;
	}

	e_size = strlen_of(config, "dev_access", eoc);
	pub_len = strlen(DEV_PUB_ACL);
	sep = (e_size > 0) ? 1 : 0;

	c->dev_acl = kzalloc(e_size + sep + pub_len + 1);
	if (!c->dev_acl) {
		EMSG("malloc dev_acl failed!\n");
		goto out;
	}

	memcpy(c->dev_acl, DEV_PUB_ACL, pub_len);
	if (e_size > 0) {
		c->dev_acl[pub_len] = ',';
		strncpy_config(c->dev_acl + pub_len + 1,
			strstr_of(config, "dev_access"), e_size);
	}

	e_size = strlen_of(config, "ipc_access", eoc);
	name_l = strlen(c->name);
	c->ipc_acl = kzalloc(e_size + 1 + name_l + 1);
	if (!c->ipc_acl) {
		EMSG("malloc ipc_acl failed!\n");
		goto out;
	}
	/* at least, TA can access itself */
	memcpy(c->ipc_acl, c->name, name_l + 1);
	if (e_size != 0) {
		c->ipc_acl[name_l] = ',';
		strncpy_config(c->ipc_acl + name_l + 1, strstr_of(config, "ipc_access"), e_size);
	}

	/* TA has additional property ?? */
	e_size = strlen_of(config, "property", eoc);
	if (e_size > 0) {
		str = strstr_of(config, "property-nr");
		if (str)
			c->nr_additionalprops = strtoul(str, NULL, 0);

		c->additionalprops = kzalloc(e_size + 1);
		if (!c->additionalprops) {
			EMSG("malloc for additional props failed!\n");
			goto out;
		}
		strlcpy(c->additionalprops, strstr_of(config, "property"), e_size + 1);
	}

	DMSG("%s@%s\n", c->name, c->path);
	DMSG("stack %d, heap %ld single_instance %d version: %s\n",
		c->ustack_size, c->heap_size, c->single_instance, c->version);

	/*kdump("uuid", &uuid, 16);*/

	mutex_init(&c->inst_lock);

	if (!c->privilege)
		fs_create(c->name);

	mutex_lock(&pconf_mtx);
	list_add_tail(&c->node, &pconfigs);
	mutex_unlock(&pconf_mtx);

	return 0;

out:
	kfree(c->additionalprops);
	kfree(c->dev_acl);
	kfree(c->ipc_acl);
	kfree(c);
	return -ENOMEM;
}

static int process_config_load(int fd)
{
	int ret = 0;
	int offset = 0, rd_size = 0;
	char *config = NULL;

	config = kmalloc(PAGE_SIZE);
	if (!config) {
		EMSG("malloc %ld size failed\n", PAGE_SIZE);
		return -ENOMEM;
	}

	/* max. 4095 bytes */
	do {
		rd_size = sys_read(fd, config + offset, PAGE_SIZE - offset - 1);
		if (rd_size > 0)
			offset += rd_size;
	} while (rd_size > 0);

	config[offset] = 0;

	ret = process_config_set(config, offset, true);
	if (ret < 0)
		EMSG("parse config error\n");

	kfree(config);
	return ret;
}

static void __init process_config_init(void)
{
	int fd = -1;
	const char *path = "/apps/";
	const char *ext = ".config";
	char name[FS_NAME_MAX * 2];
	struct dirent *d = NULL;
	DIR *dir = NULL;

	dir = opendir(path);
	if (!dir) {
		EMSG("open %s failed\n", path);
		return;
	}

	while (1) {
		strlcpy(name, path, sizeof(name));
		if ((d = readdir(dir)) != NULL) {
			if (strstr(d->d_name, ext)) {
				if (strlen(strstr(d->d_name, ext)) != strlen(ext))
					continue;
				strlcat(name, d->d_name, sizeof(name));
				IMSG("Processing %s\n", name);
				fd = sys_open((const char *)name, O_RDONLY);
				if (fd < 0) {
					EMSG("Opening %s failed\n", name);
					continue;
				}
				if (process_config_load(fd) != 0)
					EMSG("process_config_read failed\n");
				sys_close(fd);
			}
		} else {
			break;
		}
	}

	closedir(dir);
}

MODULE_INIT_CORE(process_config_init);
