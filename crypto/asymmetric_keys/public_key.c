/* In-software asymmetric public-key crypto subtype
 *
 * See Documentation/crypto/asymmetric-keys.txt
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKEY: "fmt
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/scatterlist.h>
#include <keys/asymmetric-subtype.h>
#include <crypto/public_key.h>
#include <crypto/akcipher.h>
#include <crypto/sm2.h>
#include <crypto/sm3_base.h>

MODULE_DESCRIPTION("In-software asymmetric public-key subtype");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

/*
 * Provide a part of a description of the key for /proc/keys.
 */
static void public_key_describe(const struct key *asymmetric_key,
				struct seq_file *m)
{
	struct public_key *key = asymmetric_key->payload.data[asym_crypto];

	if (key)
		seq_printf(m, "%s.%s", key->id_type, key->pkey_algo);
}

/*
 * Destroy a public key algorithm key.
 */
void public_key_free(struct public_key *key)
{
	if (key) {
		kfree(key->key);
		kfree(key);
	}
}
EXPORT_SYMBOL_GPL(public_key_free);

/*
 * Destroy a public key algorithm key.
 */
static void public_key_destroy(void *payload0, void *payload3)
{
	public_key_free(payload0);
	public_key_signature_free(payload3);
}

#if IS_REACHABLE(CONFIG_CRYPTO_SM2)
static int cert_sig_digest_update(const struct public_key_signature *sig,
				  struct crypto_akcipher *tfm_pkey)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t desc_size;
	unsigned char dgst[SM3_DIGEST_SIZE];
	int ret;

	BUG_ON(!sig->data);

	ret = sm2_compute_z_digest(tfm_pkey, SM2_DEFAULT_USERID,
					SM2_DEFAULT_USERID_LEN, dgst);
	if (ret)
		return ret;

	tfm = crypto_alloc_shash(sig->hash_algo, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto error_free_tfm;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error_free_desc;

	ret = crypto_shash_update(desc, dgst, SM3_DIGEST_SIZE);
	if (ret < 0)
		goto error_free_desc;

	ret = crypto_shash_finup(desc, sig->data, sig->data_size, sig->digest);

error_free_desc:
	kfree(desc);
error_free_tfm:
	crypto_free_shash(tfm);
	return ret;
}
#else
static inline int cert_sig_digest_update(
	const struct public_key_signature *sig,
	struct crypto_akcipher *tfm_pkey)
{
	return -ENOTSUPP;
}
#endif /* ! IS_REACHABLE(CONFIG_CRYPTO_SM2) */

/*
 * Verify a signature using a public key.
 */
int public_key_verify_signature(const struct public_key *pkey,
				const struct public_key_signature *sig)
{
	struct crypto_wait cwait;
	struct crypto_akcipher *tfm;
	struct akcipher_request *req;
	struct scatterlist src_sg[2];
	const char *alg_name;
	char alg_name_buf[CRYPTO_MAX_ALG_NAME];
	void *digest;
	int ret;

	pr_devel("==>%s()\n", __func__);

	BUG_ON(!pkey);
	BUG_ON(!sig);
	BUG_ON(!sig->s);

	if (!sig->digest)
		return -ENOPKG;

	alg_name = sig->pkey_algo;
	if (strcmp(sig->pkey_algo, "rsa") == 0) {
		/* The data wangled by the RSA algorithm is typically padded
		 * and encoded in some manner, such as EMSA-PKCS1-1_5 [RFC3447
		 * sec 8.2].
		 */
		if (snprintf(alg_name_buf, CRYPTO_MAX_ALG_NAME,
			     "pkcs1pad(rsa,%s)", sig->hash_algo
			     ) >= CRYPTO_MAX_ALG_NAME)
			return -EINVAL;
		alg_name = alg_name_buf;
	}

	tfm = crypto_alloc_akcipher(alg_name, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = -ENOMEM;
	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto error_free_tfm;

	ret = crypto_akcipher_set_pub_key(tfm, pkey->key, pkey->keylen);
	if (ret)
		goto error_free_req;

	if (sig->pkey_algo && strcmp(sig->pkey_algo, "sm2") == 0 &&
	    sig->data_size) {
		ret = cert_sig_digest_update(sig, tfm);
		if (ret)
			goto error_free_req;
	}

	ret = -ENOMEM;
	digest = kmemdup(sig->digest, sig->digest_size, GFP_KERNEL);
	if (!digest)
		goto error_free_req;

	sg_init_table(src_sg, 2);
	sg_set_buf(&src_sg[0], sig->s, sig->s_size);
	sg_set_buf(&src_sg[1], digest, sig->digest_size);
	akcipher_request_set_crypt(req, src_sg, NULL, sig->s_size,
				   sig->digest_size);
	crypto_init_wait(&cwait);
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &cwait);
	ret = crypto_wait_req(crypto_akcipher_verify(req), &cwait);

	kfree(digest);
error_free_req:
	akcipher_request_free(req);
error_free_tfm:
	crypto_free_akcipher(tfm);
	pr_devel("<==%s() = %d\n", __func__, ret);
	if (WARN_ON_ONCE(ret > 0))
		ret = -EINVAL;
	return ret;
}
EXPORT_SYMBOL_GPL(public_key_verify_signature);

static int public_key_verify_signature_2(const struct key *key,
					 const struct public_key_signature *sig)
{
	const struct public_key *pk = key->payload.data[asym_crypto];
	return public_key_verify_signature(pk, sig);
}

/*
 * Public key algorithm asymmetric key subtype
 */
struct asymmetric_key_subtype public_key_subtype = {
	.owner			= THIS_MODULE,
	.name			= "public_key",
	.name_len		= sizeof("public_key") - 1,
	.describe		= public_key_describe,
	.destroy		= public_key_destroy,
	.verify_signature	= public_key_verify_signature_2,
};
EXPORT_SYMBOL_GPL(public_key_subtype);
