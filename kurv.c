#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>
#include <glob.h>

#include "monocypher/monocypher.h"
#include "base64.h"

// PATH_MAX is too crazy, be conservative and just define it ourselves.
#define NAME_MAX 255
#define die(...) {\
    fprintf(stderr, __VA_ARGS__);\
    exit(1);\
}
#define B64_KEY_SIZE 44
#define B64_SIG_SIZE 88
#define SIGN_BUF_SIZE (1024 * 4096)

const uint8_t SIG_START[] = "\n----BEGIN KURV SIGNATURE----\n";
const uint8_t SIG_END[] = "\n----END KURV SIGNATURE----\n";
const uint8_t USAGE[] =
    "usage:\n"
    "   kurv -h\n"
    "   kurv -g <name>                       generate keypair <name>.pub and <name>.priv\n"
    "   kurv -s <file> -k <privkey>          sign <file> with <privkey>\n"
    "   kurv -c <signed-file> [-k <pubkey>]  check <signed-file> with <pubkey>\n"
    "                                        if <pubkey> is not specified, search\n"
    "                                        $KURV_KEYRING for a matching pubkey.\n"
    ;


void random_buffer(uint8_t buf[], size_t length)
{
    // Since length is always == 32 this should always be fine.
    int rv = getrandom(buf, length, 0);
    if (rv < 0)
        die("getrandom() returned %d\n", rv);
}


void write_or_die(const char* filename, const uint8_t buf[], size_t bufsize)
{
    FILE* fp = fopen(filename, "w");
    if (fp == NULL)
        die("cannot open file: %s\n", filename);
    if (fwrite(buf, sizeof(uint8_t), bufsize, fp) < bufsize)
        die("cannot write into %s\n", filename);
    fclose(fp);
}


int read_b64_stream(uint8_t* output, size_t output_size,
        uint8_t* b64_buf, size_t b64_buf_size,
        FILE* fp)
{
    if ((fread(b64_buf, sizeof(uint8_t), b64_buf_size, fp) != b64_buf_size)
            || ferror(fp)
            || (b64_validate(b64_buf, b64_buf_size) != 0)
            || (b64_decoded_size(b64_buf, b64_buf_size) != output_size)) {
        // we may have some partial information in here,
        // just wipe to be sure
        crypto_wipe(b64_buf, b64_buf_size);
        return 1;
    }
    // Store inside output
    b64_decode(output, b64_buf, b64_buf_size);
    crypto_wipe(b64_buf, b64_buf_size);
    return 0;
}


uint8_t* read_file(FILE* fp, size_t* size)
{
    // Keep trying to read from fp, remember that
    // fp can be stdin, so we just need to use `feof'.
    size_t total = 0;
    size_t bufsize = SIGN_BUF_SIZE;
    uint8_t* buf = calloc(bufsize, sizeof(uint8_t));
    if (buf == NULL)
        die("malloc() failed\n");
    for (;;) {
        int n = fread(buf + total, sizeof(uint8_t), SIGN_BUF_SIZE, fp);
        if (n >= 0) {
            total += n;
        }
        if (feof(fp)) break;
        else {
            // If we are not at eof, realloc
            bufsize += SIGN_BUF_SIZE;
            buf = reallocarray(buf, bufsize, sizeof(uint8_t));
            if (buf == NULL)
                die("realloc() failed\n");
        }
        if (ferror(fp))
            die("read error\n");
    }
    *size = total;
    return buf;
}


// Find the b64 signature in the buffer.
//  1) write b64 signature to b64_sig
//  2) return size of text w/o armoured signature.
int get_signature(uint8_t* b64_sig,
                  const uint8_t* buf, size_t bufsize)
{
    size_t start_size = sizeof(SIG_START),
           sig_size   = B64_SIG_SIZE,
           end_size   = sizeof(SIG_END),
           total      = start_size + sig_size + end_size;
    // Check if we can find the armour
    if ((memcmp(buf + bufsize - end_size, SIG_END, end_size)) != 0
            || (memcmp(buf + bufsize - total, SIG_START, start_size) != 0)) {
        return -1;
    }
    // Copy into b64_sig
    memcpy(b64_sig,
           buf + bufsize - sig_size - end_size,
           sig_size);
    return bufsize - total;
}


void check_keyring(FILE* fp)
{
    uint8_t public_key     [32],
            signature      [64],
            b64_public_key [B64_KEY_SIZE],
            b64_signature  [B64_SIG_SIZE];

    size_t bufsize;
    uint8_t *buf = read_file(fp, &bufsize);

    if ((bufsize = get_signature(b64_signature, buf, bufsize)) < 0)
        die("cannot find signature in file\n");

    b64_decode(signature, b64_signature, B64_SIG_SIZE);

    // Build glob path
    char* keyring_path = getenv("KURV_KEYRING");
    if (keyring_path == NULL) {
        die("$KURV_KEYRING unset\n");
    }

    size_t length = strlen(keyring_path);
    char* glob_pattern = calloc(length + 6 + 1, sizeof(uint8_t));
    if (glob_pattern == NULL)
        die("cannot malloc()\n");

    memcpy(glob_pattern, keyring_path, length);

    // Check if it ends with /
    if (keyring_path != NULL && keyring_path[length - 1] != '/')
        memcpy(glob_pattern + length, "/*.pub", 6);
    else
        memcpy(glob_pattern + length, "*.pub", 5);

    // Find a matching pubkey
    glob_t globbuf;
    glob(glob_pattern, GLOB_TILDE, NULL, &globbuf);
    for (size_t i = 0; i < globbuf.gl_pathc; i++) {
        FILE* pk_fp = fopen(globbuf.gl_pathv[i], "r");
        if (pk_fp == NULL)
            continue;

        // Ignore bad public key files.
        if (read_b64_stream(public_key, 32,
                            b64_public_key, B64_KEY_SIZE,
                            pk_fp) != 0) {
            continue;
        }

        if (crypto_check(signature,
                         public_key,
                         buf, bufsize) == 0) {
            printf("%s\n", globbuf.gl_pathv[i]);
            exit(0);
        }
        fclose(pk_fp);
    }

    globfree(&globbuf);
    free(glob_pattern);
    free(buf);
    fprintf(stderr, "unable to find signer.\n");
    exit(1);
}


void check(FILE* fp, FILE* pk_fp)
{
    uint8_t public_key     [32],
            signature      [64],
            b64_public_key [B64_KEY_SIZE],
            b64_signature  [B64_SIG_SIZE];
    if (read_b64_stream(public_key, 32,
                        b64_public_key, B64_KEY_SIZE,
                        pk_fp) != 0)
        die("bad public key\n");

    size_t bufsize;
    uint8_t *buf = read_file(fp, &bufsize);

    if ((bufsize = get_signature(b64_signature, buf, bufsize)) < 0)
        die("cannot find signature in file\n");

    if ((b64_validate(b64_signature, B64_SIG_SIZE) != 0)
            || (b64_decoded_size(b64_signature, B64_SIG_SIZE) != 64)) {
        die("invalid signature\n");
    }

    b64_decode(signature, b64_signature, B64_SIG_SIZE);
    int rv = crypto_check(signature,
                          public_key,
                          buf, bufsize);
    free(buf);
    if (rv != 0) {
        // bad
        die("invalid signature\n");
    }
}


// Sign a file stream fp with secret key from sk_fp
void sign(FILE* fp, FILE* sk_fp)
{
    uint8_t secret_key[32],
            public_key[32],
            signature[64],
            b64_signature[B64_SIG_SIZE],
            b64_secret_key[B64_KEY_SIZE];

    if (read_b64_stream(secret_key, sizeof(secret_key),
                        b64_secret_key, B64_KEY_SIZE,
                        sk_fp) != 0)
        die("bad private key\n");

    size_t bufsize;
    uint8_t* buf = read_file(fp, &bufsize);

    crypto_sign_public_key(public_key, secret_key);
    crypto_sign(signature,
                secret_key,
                public_key,
                buf, bufsize);
    crypto_wipe(secret_key, 32);
    crypto_wipe(public_key, 32);

    b64_encode(b64_signature, signature, 64);

    // Write to stdout
    fwrite(buf,           sizeof(uint8_t), bufsize,               stdout);
    fwrite(SIG_START,     sizeof(uint8_t), sizeof(SIG_START),     stdout);
    fwrite(b64_signature, sizeof(uint8_t), sizeof(b64_signature), stdout);
    fwrite(SIG_END,       sizeof(uint8_t), sizeof(SIG_END),       stdout);
    free(buf);
}


// Generates a .pub and .priv file
void generate(char* base)
{
    uint8_t secret_key[32],
            public_key[32],
            secret_key_b64[B64_KEY_SIZE],
            public_key_b64[B64_KEY_SIZE];
    random_buffer(secret_key, 32);
    crypto_sign_public_key(public_key, secret_key);

    b64_encode(secret_key_b64, secret_key, 32);
    b64_encode(public_key_b64, public_key, 32);

    // Write private key
    // Allow space for the suffix and a null byte.
    size_t length = strlen(base);
    if (length > NAME_MAX - 5 - 1)
        die("base length too long, must be between 0 and %d\n", NAME_MAX - 5 - 1);
    char path[NAME_MAX];
    memset(path, 0, NAME_MAX);
    memcpy(path, base, length);
    memcpy(path+length, ".priv", 5);

    write_or_die(path, secret_key_b64, B64_KEY_SIZE);
    crypto_wipe(secret_key, 32);
    crypto_wipe(secret_key_b64, B64_KEY_SIZE);

    // Write public key
    memset(path, 0, NAME_MAX);
    memcpy(path, base, length);
    memcpy(path+length, ".pub", 4);

    write_or_die(path, public_key_b64, B64_KEY_SIZE);
    crypto_wipe(public_key, 32);
    crypto_wipe(public_key_b64, B64_KEY_SIZE);
}


FILE* fopen_with_stdin(char* filename)
{
    if (strcmp(filename, "-") == 0)
        return stdin;
    // Otherwise have to do some work
    FILE* fp = fopen(filename, "r");
    if (fp == NULL)
        die("cannot open file: %s\n", filename);
    return fp;
}


int main(int argc, char** argv)
{
    FILE* fp = NULL;     // File to sign
    FILE* key_fp = NULL; // Priv or pubkey file
    char* base = NULL;   // base for generate
    char action;
    int c;
    int rv = 0;

    while ((c = getopt(argc, argv, "hg:s:c:k:")) != -1)
        switch (c) {
            case 'h':
                fwrite(USAGE, 1, sizeof(USAGE), stdout);
                exit(0);
                break;
            case 'g': action = 'g'; base = optarg; break;
            case 's': action = 's'; fp = fopen_with_stdin(optarg); break;
            case 'c': action = 'c'; fp = fopen_with_stdin(optarg); break;
            case 'k':           key_fp = fopen_with_stdin(optarg); break;
            default:
                fwrite(USAGE, 1, sizeof(USAGE), stderr);
                rv = 1;
                break;
        }

    if ((key_fp == stdin) && (fp == stdin))
        die("key-file and file cannot both be stdin\n");

    switch (action) {
        case 'g': generate(base);    break;
        case 's':
            if (key_fp == NULL)
                die("key file not specified\n");
            sign(fp, key_fp);
            break;
        case 'c':
            if (key_fp != NULL) {
                check(fp, key_fp);
            } else {
                check_keyring(fp);
            }
            break;
    }

    if (    fp != NULL) fclose(fp);
    if (key_fp != NULL) fclose(key_fp);
    return rv;
}
