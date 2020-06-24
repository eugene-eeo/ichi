#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "base64.h"
#include "monocypher/monocypher.h"

//
// Macros
//
#define READ_SIZE (4096)
#define B64_KEY_SIZE 44  // b64_encoded_size(32)
#define B64_SIG_SIZE 88  // b64_encoded_size(64)
#define die(...) {\
    fwrite("kurv: ", 1, 7, stderr);\
    fprintf(stderr, __VA_ARGS__);\
    fwrite("\n", 1, 1, stderr);\
    exit(1);\
}
#define errdie(prefix) {\
    err((prefix));\
    exit(1);\
}
#define err(prefix) {\
    fwrite("kurv: ", 1, 7, stderr);\
    perror((prefix));\
}
#define setaction(c) {\
    if (action != 0)\
        die("invalid usage: see kurv -h.");\
    action = (c);\
}

const uint8_t SIG_START[] = "\n----BEGIN KURV SIGNATURE----\n";
const uint8_t SIG_END[] =   "\n----END KURV SIGNATURE----\n";
const uint8_t USAGE[] =
    "usage:\n"
    "   kurv -h\n"
    "   kurv -g <name>\n"
    "   kurv -s|-c|-d [-P <privkey>] [-p <pubkey>] [<file>]\n"
    "\n"
    "arguments:\n"
    "   <file>    Defaults to stdin if not given.\n\n"
    "options:\n"
    "   -h        Show help page.\n"
    "   -g        Generate keypair in <name>.pub and <name>.priv.\n"
    "   -P <key>  Specify private key file.\n"
    "   -p <key>  Specify public key file.\n"
    "   -s        Sign <file> using supplied private key.\n"
    "   -c        Check <file> using optional public key.\n"
    "             If no public key is specified, search for a\n"
    "             valid public key (file ending in .pub) in \n"
    "             $KURV_KEYRING.\n"
    "   -i        Print the key used upon successful check.\n"
    "   -o        Print file contents upon successful check.\n"
    "   -d        Detach signature from the signed file.\n"
    "\n"
    ;
#define SIG_START_LEN (sizeof(SIG_START)-1)
#define SIG_END_LEN   (sizeof(SIG_END)-1)

//
// Read exactly n bytes into buf.
// Return -1 on failure.
//
int read_exactly(uint8_t* buf, const size_t n, FILE* fp)
{
    if (fread(buf, 1, n, fp) != n) {
        err("kurv: fread");
        return -1;
    }
    return 0;
}

//
// Decode exactly n bytes
//
int decode_exactly(      uint8_t* buf, size_t bufsize,
                   const uint8_t* b64, size_t b64size)
{
    if (b64_validate(b64, b64size) != 0 || b64_decoded_size(b64, b64size) != bufsize)
        return -1;
    b64_decode(buf, b64, b64size);
    return 0;
}

//
// Read entirety of fp into memory, set bufsize as
// appropriate, and return ptr to the buffer.
// Returns NULL if any errors occured.
//
uint8_t* read_file(FILE* fp, size_t* bufsize)
{
    size_t total = 0;           // total buffer size
    size_t size = READ_SIZE;    // current buffer size
    uint8_t* buf = calloc(size, sizeof(uint8_t));
    if (buf == NULL) {
        err("kurv: calloc");
        return NULL;
    }

    size_t n;
    while (!feof(fp) && (n = fread(buf + total, sizeof(uint8_t), READ_SIZE, fp)) > 0) {
        total += n;
        if (size <= total) {
            size += 2 * READ_SIZE;
            uint8_t* new = reallocarray(buf, size, sizeof(uint8_t));
            if (new == NULL) {
                err("kurv: reallocarray");
                free(buf);
                return NULL;
            }
            buf = new;
        }
    }

    if (ferror(fp)) {
        err("kurv: fread");
        free(buf);
        return NULL;
    }

    *bufsize = total;
    return buf;
}

//
// Try to find the b64 signature in the buffer, write
// raw signature to signature, and write the new buffer
// size (w/o signature to &bufsize).
//
int find_signature(uint8_t signature[64], const uint8_t* buf, size_t* bufsize_ptr)
{
    size_t start_size = SIG_START_LEN,
           sig_size   = B64_SIG_SIZE,
           end_size   = SIG_END_LEN,
           sig_total  = start_size + sig_size + end_size,
           bufsize    = *bufsize_ptr;

    uint8_t b64_sig[B64_SIG_SIZE];

    if (bufsize < sig_total
            || memcmp(SIG_END,   buf + bufsize - end_size, end_size) != 0
            || memcmp(SIG_START, buf + bufsize - sig_total, start_size) != 0)
        return -1;

    memcpy(b64_sig, buf + bufsize - sig_size - end_size, sig_size);
    if (decode_exactly(signature, 64,
                       b64_sig, B64_SIG_SIZE) != 0)
        return -1;
    *bufsize_ptr = bufsize - sig_total;
    return 0;
}

//
// Read from keyfile
//
int find_key_in_file(uint8_t key[32], FILE* fp)
{
    uint8_t b64_key[B64_KEY_SIZE];
    if (read_exactly(b64_key, B64_KEY_SIZE, fp) != 0
            || decode_exactly(key, 32, b64_key, B64_KEY_SIZE) != 0) {
        crypto_wipe(b64_key, sizeof(b64_key));
        return -1;
    }
    return 0;
}

//
// Concatenate a with b, adding the NUL byte at the end.
//
void str_concat(char* dst, const char* a, const char* b)
{
    size_t a_size = strlen(a),
           b_size = strlen(b);
    memcpy(dst,          a, a_size);
    memcpy(dst + a_size, b, b_size);
    dst[a_size + b_size] = 0;
}

//
// Check if a string src ends with suffix
//
int str_endswith(const char* src, const char* suffix)
{
    size_t src_size    = strlen(src),
           suffix_size = strlen(suffix);
    if (src_size < suffix_size)
        return -1;
    return memcmp(src + src_size - suffix_size, suffix, suffix_size);
}

//
// Needed for generate(...): version of fopen supporting flags
//
FILE* safe_fopen_w(char* fn, int o_mode)
{
    int flags = O_WRONLY | O_CREAT | O_TRUNC;
    int fd = open(fn, flags, o_mode);
    if (fd == -1) {
        err("open");
        return NULL;
    }
    FILE* fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        err("fdopen");
        return NULL;
    }
    return fp;
}

//
// Generates keypair at <base>.priv and <base>.pub
//
int generate(char* base)
{
    uint8_t sk[32],
            pk[32],
            b64_sk[B64_KEY_SIZE],
            b64_pk[B64_KEY_SIZE];
    if (getrandom(sk, 32, 0) < 0)
        errdie("getrandom");

    crypto_sign_public_key(pk, sk);
    b64_encode(b64_sk, sk, 32);
    b64_encode(b64_pk, pk, 32);
    crypto_wipe(sk, 32);
    crypto_wipe(pk, 32);

    // Reserve enough space for .priv and .pub
    FILE* fp;
    size_t len = strlen(base);
    char* path = calloc(len + 5 + 1, sizeof(char));
    if (path == NULL)
        errdie("calloc");

    // Write private key
    str_concat(path, base, ".priv");
    fp = safe_fopen_w(path, S_IWUSR | S_IRUSR | S_IRGRP);
    if (fp == NULL
            || fwrite(b64_sk, 1, sizeof(b64_sk), fp) != sizeof(b64_sk)
            || fwrite("\n", 1, 1, fp) < 0
            || fclose(fp) != 0)
        errdie("cannot write private key");
    crypto_wipe(b64_sk, sizeof(b64_sk));
    fprintf(stderr, "kurv: wrote private key in '%s'.\n", path);

    // Write public key
    str_concat(path, base, ".pub");
    fp = safe_fopen_w(path, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
    if (fp == NULL
            || fwrite(b64_pk, 1, sizeof(b64_pk), fp) != sizeof(b64_pk)
            || fwrite("\n", 1, 1, fp) < 0
            || fclose(fp) != 0)
        errdie("cannot write public key");
    crypto_wipe(b64_pk, sizeof(b64_pk));
    fprintf(stderr, "kurv: wrote public key in '%s'.\n", path);

    free(path);
    return 0;
}

//
// Sign a given file stream with the given signature stream sk_fp.
//
int sign(FILE* fp, FILE* sk_fp)
{
    // Make sure to crypto_wipe!
    uint8_t sk      [32],
            pk      [32],  // used when computing signature
            sig     [64],
            b64_sig [B64_SIG_SIZE];

    if (find_key_in_file(sk, sk_fp) == -1) {
        crypto_wipe(sk, 32);
        die("invalid private key.");
    }

    size_t msg_size;
    uint8_t* msg = read_file(fp, &msg_size);
    if (msg == NULL) {
        crypto_wipe(sk, 32);
        errdie("cannot read file");
    }

    crypto_sign_public_key(pk, sk);
    crypto_sign(sig,
                sk, pk,
                msg, msg_size);
    b64_encode(b64_sig, sig, 64);
    crypto_wipe(sk, 32);
    crypto_wipe(pk, 32);

    fwrite(msg,       sizeof(uint8_t), msg_size,        stdout);
    fwrite(SIG_START, sizeof(uint8_t), SIG_START_LEN,   stdout);
    fwrite(b64_sig,   sizeof(uint8_t), sizeof(b64_sig), stdout);
    fwrite(SIG_END,   sizeof(uint8_t), SIG_END_LEN,     stdout);
    free(msg);
    return 0;
}

//
// Check against keyring
//
int check_keyring(FILE* fp, int should_show_id, int should_show_og)
{
    char* keyring_dir = getenv("KURV_KEYRING");
    if (keyring_dir == NULL)
        die("$KURV_KEYRING is not set.");

    // Read message first.
    size_t msg_size;
    uint8_t* msg = read_file(fp, &msg_size);
    if (msg == NULL)
        die("error reading file.");

    uint8_t sig [64];
    if (find_signature(sig, msg, &msg_size) < 0)
        die("cannot find / malformed signature.");

    DIR* dir = opendir(keyring_dir);
    struct dirent *dp;
    if (dir == NULL) {
        err("opendir");
        die("cannot open keyring directory '%s'", keyring_dir);
    }
    int dir_fd = dirfd(dir);
    if (dir_fd < 0)
        errdie("dirfd");

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0
                || strcmp(dp->d_name, "..") == 0
                || str_endswith(dp->d_name, ".pub") != 0)
            continue;

        uint8_t pk[32];
        int fd = openat(dir_fd, dp->d_name, O_RDONLY);
        if (fd < 0) continue;

        FILE* pk_fp = fdopen(fd, "r");
        if (pk_fp == NULL) {
            close(fd);
            continue;
        }
        if (find_key_in_file(pk, pk_fp) != 0 || crypto_check(sig, pk, msg, msg_size) != 0) {
            fclose(pk_fp);
            continue;
        }

        // Found it
        if (should_show_id)
            printf("%s%s%s\n",
                   keyring_dir,
                   keyring_dir[strlen(keyring_dir)-1] == '/' ? "" : "/",
                   dp->d_name);
        if (should_show_og) fwrite(msg, sizeof(uint8_t), msg_size, stdout);
        fclose(pk_fp);
        closedir(dir);
        free(msg);
        return 0;
    }

    die("cannot find a signer.");
    exit(1);
}

//
// Check that a file is signed by a given pk_fp
//
int check(FILE* fp, FILE* pk_fp, char* pk_fn, int should_show_id, int should_show_og)
{
    // It's fine to not crypto_wipe in this function, we are
    // only dealing with public keys.
    uint8_t pk  [32],
            sig [64];

    if (find_key_in_file(pk, pk_fp) == -1)
        die("invalid public key.");

    size_t msg_size;
    uint8_t* msg = read_file(fp, &msg_size);
    if (msg == NULL)
        die("error reading file.");

    if (find_signature(sig, msg, &msg_size) < 0)
        die("cannot find / malformed signature.");

    if (crypto_check(sig,
                     pk,
                     msg, msg_size) != 0)
        die("invalid signature.");

    if (should_show_id) printf("%s\n", pk_fn);
    if (should_show_og) fwrite(msg, sizeof(uint8_t), msg_size, stdout);
    free(msg);
    return 0;
}

//
// Detach a signature from the file.
//
int detach(FILE* fp)
{
    size_t msg_size;
    uint8_t* msg = read_file(fp, &msg_size);
    if (msg == NULL)
        die("error reading file.");

    uint8_t sig[64]; // unusued
    if (find_signature(sig, msg, &msg_size) < 0)
        die("cannot find / malformed signature.");

    fwrite(msg, sizeof(uint8_t), msg_size, stdout);
    free(msg);
    return 0;
}

//
// Warn if user specified a .priv instead of .pub
// or vice versa.
//
void keyfile_warn(char* fn, int is_priv)
{
    if (str_endswith(fn, is_priv ? ".priv" : ".pub") != 0)
        fprintf(stderr, "kurv: warning: %s key file doesn't end in %s\n",
                is_priv ? "private" : "public",
                is_priv ? ".priv" : ".pub");
}

//
// Utility for opening a file or dying
//
FILE* fopen_or_die(const char* ctx, const char* fn)
{
    FILE* fp = fopen(fn, "r");
    if (fp == NULL) {
        err("fopen");
        die("cannot open '%s' for %s.", fn, ctx);
    }
    return fp;
}

int main(int argc, char** argv)
{
    FILE* fp     = stdin;
    FILE* pk_fp  = NULL;
    FILE* sk_fp  = NULL;
    char* pk_fn  = "";
    char* base   = NULL;
    char  action = 0;
    int should_show_id = 0;
    int should_show_og = 0;
    int c;
    while ((c = getopt(argc, argv, "hg:scdp:P:io")) != -1)
        switch (c) {
            default:  exit(1);
            case 'h': fwrite(USAGE, sizeof(char), sizeof(USAGE), stdout); exit(0); break;
            case 'g': setaction('g'); base = optarg; break;
            case 's': setaction('s'); break;
            case 'c': setaction('c'); break;
            case 'd': setaction('d'); break;
            case 'P': keyfile_warn(optarg, 1); sk_fp = fopen_or_die("private key", optarg); break;
            case 'p': keyfile_warn(optarg, 0); pk_fp = fopen_or_die("public key",  optarg);
                      pk_fn = optarg;
                      break;
            case 'i': should_show_id = 1; break;
            case 'o': should_show_og = 1; break;
        }

    int rv = 1;
    if (action == 0) {
        die("invalid usage. see kurv -h.");
    } else if (action == 'g') {
        rv = generate(base);
    } else {
        if (optind < argc) {
            if (optind + 1 != argc) die("invalid usage. see kurv -h.");
            char* fn = argv[optind];
            switch (action) {
                case 's': fp = fopen_or_die("signing", fn); break;
                case 'c': fp = fopen_or_die("checking", fn); break;
                case 'd': fp = fopen_or_die("detach", fn); break;
            }
        }
        switch (action) {
            case 's':
                if (sk_fp == NULL) die("no private key file specified.");
                rv = sign(fp, sk_fp);
                break;
            case 'c':
                rv = (pk_fp == NULL)
                    ? check_keyring(fp, should_show_id, should_show_og)
                    : check(fp, pk_fp, pk_fn, should_show_id, should_show_og);
                break;
            case 'd':
                rv = detach(fp);
                break;
        }
    }
    if (fp != NULL)    fclose(fp);
    if (pk_fp != NULL) fclose(pk_fp);
    if (sk_fp != NULL) fclose(sk_fp);
    exit(rv);
}
