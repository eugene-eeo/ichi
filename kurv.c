#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <dirent.h>
#include <unistd.h>

#include "monocypher/monocypher.h"
#include "base64.h"

#define die(...) {\
    fprintf(stderr, __VA_ARGS__);\
    exit(1);\
}
#define B64_KEY_SIZE 44
#define B64_SIG_SIZE 88
#define SIGN_BUF_SIZE (1024 * 4096)

const uint8_t SIG_START[] = "\n----BEGIN KURV SIGNATURE----\n";
const uint8_t SIG_END[] = "\n----END KURV SIGNATURE----\n";
const uint8_t HELP[] = "";
const uint8_t USAGE[] =
    "Usage:\n"
    "   kurv -h\n"
    "   kurv -g <name>\n"
    "   kurv -s <file> -k <privkey>\n"
    "   kurv -c <signed-file> [-k <pubkey>] [-i] [-o]\n"
    "\n"
    "Options:\n"
    "   -h         show help page\n"
    "   -g         generate keypair <name>.pub and <name>.priv\n"
    "   -k <key>   specify the pub/priv key file for signing/checking\n"
    "   -s <file>  sign <file> using the key given\n"
    "   -c <signed-file> check signed file using the key given (if any)\n"
    "                    if no key file is specified, try .pub files in\n"
    "                    $KURV_KEYRING until we find a valid key.\n"
    "   -i         output the <key> used upon successful check.\n"
    "   -o         output the data upon successful check.\n"
    "\n"
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
        if (n > 0)
            total += n;
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
           end_size   = sizeof(SIG_END);
    size_t total      = start_size + sig_size + end_size;

    // Check if we can find the armour
    if (bufsize < total
            || (memcmp(buf + bufsize - end_size, SIG_END, end_size)) != 0
            || (memcmp(buf + bufsize - total, SIG_START, start_size) != 0)) {
        return -1;
    }
    // Copy into b64_sig
    memcpy(b64_sig,
           buf + bufsize - sig_size - end_size,
           sig_size);
    return bufsize - total;
}


void join_path(char* buf,
               char* prefix, size_t prefix_size,
               char* suffix, size_t suffix_size) {
    memcpy(buf, prefix, prefix_size);
    // check if there is a trailing slash!
    if (buf[prefix_size-1] != '/') {
        buf[prefix_size] = '/';
        prefix_size++;
    }
    memcpy(buf + prefix_size, suffix, suffix_size);
    buf[prefix_size + suffix_size] = '\0';
}


void check_keyring(FILE* fp, int output_id, int output_contents)
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

    size_t length;
    char* keyring_path = getenv("KURV_KEYRING");
    if (keyring_path == NULL || (length = strlen(keyring_path)) == 0)
        die("$KURV_KEYRING unset\n");

    char* pathname = malloc(strlen(keyring_path) + 255 + 1);
    if (pathname == NULL)
        die("malloc() failed\n");

    DIR* dir = opendir(keyring_path);
    if (dir == NULL)
        die("failed to open directory $KURV_KEYRING\n");
    struct dirent *dp;

    // Find a matching pubkey
    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;

        join_path(pathname,
                  keyring_path, length,
                  dp->d_name, strlen(dp->d_name));

        FILE* pk_fp = fopen(pathname, "r");
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
            if (output_id)       printf("%s\n", dp->d_name);
            if (output_contents) fwrite(buf, 1, bufsize, stdout);
            exit(0);
        }
        fclose(pk_fp);
    }

    free(buf);
    fprintf(stderr, "unable to find signer.\n");
    exit(1);
}


void check(FILE* fp, FILE* pk_fp, char* pk_fn, int output_id, int output_contents)
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

    if (crypto_check(signature,
                     public_key,
                     buf, bufsize) != 0)
        die("invalid signature\n");

    // output
    if (output_id)       printf("%s\n", pk_fn);
    if (output_contents) fwrite(buf, 1, bufsize, stdout);
    free(buf);
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
    char* path = calloc(length + 6, sizeof(char));
    if (path == NULL)
        die("malloc() failed\n");

    memset(path, 0, length + 6);
    memcpy(path, base, length);
    memcpy(path+length, ".priv", 5);

    write_or_die(path, secret_key_b64, B64_KEY_SIZE);
    crypto_wipe(secret_key, 32);
    crypto_wipe(secret_key_b64, B64_KEY_SIZE);

    // Write public key
    memset(path, 0, length + 6);
    memcpy(path, base, length);
    memcpy(path+length, ".pub", 4);

    write_or_die(path, public_key_b64, B64_KEY_SIZE);
    crypto_wipe(public_key, 32);
    crypto_wipe(public_key_b64, B64_KEY_SIZE);
    free(path);
}


FILE* fopen_with_stdin(const char* filename, const char* type)
{
    if (strcmp(filename, "-") == 0)
        return stdin;
    // Otherwise have to do some work
    FILE* fp = fopen(filename, "r");
    if (fp == NULL)
        die("cannot open %s: %s\n", type, filename);
    return fp;
}


void help(int code)
{
    fwrite(USAGE, 1, sizeof(USAGE), stdout);
    exit(code);
}


int main(int argc, char** argv)
{
    FILE* fp = NULL;     // File to sign
    FILE* key_fp = NULL; // priv/pubkey file
    char* key_fn = "-";  // priv/pubkey filename
    char* base = NULL;   // base for generate
    char action;
    int should_output_id = 0;
    int should_output_contents = 0;
    int c;

    while ((c = getopt(argc, argv, "hg:s:c:k:io")) != -1)
        switch (c) {
            case 'h': help(0); break;
            case 'g': action = 'g'; base = optarg; break;
            case 's': action = 's'; fp = fopen_with_stdin(optarg, "file"); break;
            case 'c': action = 'c'; fp = fopen_with_stdin(optarg, "file"); break;
            case 'k':
                key_fp = fopen_with_stdin(optarg, "key file");
                key_fn = optarg;
                break;
            case 'i': should_output_id = 1; break;
            case 'o': should_output_contents = 1; break;
            default:  help(1); break;
        }

    if ((key_fp == stdin) && (fp == stdin))
        die("key-file and file cannot both be stdin\n");

    switch (action) {
        case 'g': generate(base); break;
        case 's':
            if (key_fp == NULL)
                die("key file not specified\n");
            sign(fp, key_fp);
            break;
        case 'c':
            if (key_fp != NULL) {
                check(fp, key_fp, key_fn, should_output_id, should_output_contents);
            } else {
                check_keyring(fp, should_output_id, should_output_contents);
            }
            break;
        default: help(1); break;
    }

    return 0;
}
