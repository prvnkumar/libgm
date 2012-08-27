#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<gmp.h>

#include "gm.h"


#define GM_PUB_KEY  "gm_pub.key"
#define GM_PRV_KEY  "gm_prv.key"


void generatekey()
{
    gm_pubkey_t* pub;
    gm_prvkey_t* prv;

    printf("Generating new keys...\n");
    gm_keygen(1024, &pub, &prv, gm_get_rand_devurandom);

    char * pubkey = gm_pubkey_to_hex(pub);
    char * privkey = gm_prvkey_to_hex(prv);
    FILE * pubfile = fopen(GM_PUB_KEY,"w");
    FILE * privfile = fopen(GM_PRV_KEY,"w");

    fprintf(pubfile, "%s\n", pubkey);
    fprintf(privfile, "%s\n", privkey);

    gm_freepubkey(pub);
    gm_freeprvkey(prv);

    fclose(pubfile);
    fclose(privfile);
}


void test_longtext(gm_pubkey_t* pub, gm_prvkey_t* prv)
{
    int i = 0, n = 0;
    char input[4096];
    char *output;
    gm_plaintext_t *plain, *dec; 
    gm_ciphertext_t** ctext;

    printf("Enter a string (<256 chars) : ");
    scanf("%s", input);
    printf("Plaintext :\n%s\n", input);
    plain = gm_plaintext_from_str(input);
    ctext = gm_enc(plain, &n, pub);

    printf("Ciphertext :\n");
    for(i=0;i<n;i++)
    {
        printf("%s\n",gm_ciphertext_to_hex(ctext[i]));
    }

    dec = gm_dec(ctext, n, prv);
    output = gm_plaintext_to_str(dec);
    printf("Decrypted plaintext :\n%s\nResult :", output);
    if(strcmp(input, output) == 0) printf("SUCCESS\n");
    else printf("Something went wrong! :|\n");

    gm_freeplaintext(plain);
    gm_freeplaintext(dec);
    for(i=0;i<n;i++)
    {
        gm_freeciphertext(ctext[i]);
    }
    fflush(stdout);
}


void test_homomorphic(gm_pubkey_t* pub, gm_prvkey_t* prv)
{
    int i = 0;
    int in0[4]       = {0, 0, 1, 1};
    int in1[4]       = {0, 1, 0, 1};
    int expected[4]  = {0, 1, 1, 0};
    gm_ciphertext_t* cipher0;
    gm_ciphertext_t* cipher1;
    gm_ciphertext_t* mul = (gm_ciphertext_t*)malloc(sizeof(gm_ciphertext_t));
    printf("In0\tIn1\tOut\tExp\tResult\n");
    for(i=0;i<4;i++)
    {
        cipher0 = gm_enc_bit( NULL, pub, in0[i], gm_get_rand_devurandom);
        cipher1 = gm_enc_bit( NULL, pub, in1[i], gm_get_rand_devurandom);
        gm_mul(pub, mul, cipher0, cipher1);
        int decrypt = gm_dec_bit(prv, mul);
        printf("%d\t%d\t%d\t%d\t", in0[i], in1[i], decrypt, expected[i]);
        if(decrypt == expected[i]) printf("SUCCESS\n");
        else printf("FAIL\n");
    }

    gm_freeciphertext(cipher0);
    gm_freeciphertext(cipher1);
    gm_freeciphertext(mul);
}


void readkey(gm_pubkey_t** pub,  gm_prvkey_t** prv)
{
    FILE * pubfile;
    FILE * privfile;
    if( !( (pubfile = fopen(GM_PUB_KEY,"r"))
           && (privfile = fopen(GM_PRV_KEY,"r"))
         ))
    {
        if(pubfile) fclose(pubfile);
        fprintf(stderr, "Keys don't exist in the default location... ");
        generatekey();
        if( !( (pubfile = fopen(GM_PUB_KEY,"r"))
               && (privfile = fopen(GM_PRV_KEY,"r"))
          ))
        {
            fprintf(stderr, "Error: Failed to get keys.");
            exit(8);
        }

    }

    char n[4096], x[4096], p[4096], q[4096];
    fscanf(pubfile,"%s%s",n, x);
    fscanf(privfile,"%s%s",p, q);
    fclose(pubfile);
    fclose(privfile);

    *pub = gm_pubkey_from_hex(n, x);
    *prv = gm_prvkey_from_hex(p, q);
    return;
}


void usage()
{
    printf("Usage :\n"
            "-k : Generate new keys\n"
            "-h : Test the homomorphic property of the cryptosystem\n"
            "-s : Encrypt and decrypt a string\n");
    exit(8);
}

int main(int argc, char* argv[])
{
    int i;
    gm_pubkey_t* pub;
    gm_prvkey_t* prv;

    if(argc < 2)
    {
        usage();
    }
    for(i=1; i<argc; i++)
    {
        if(argv[i][0] == '-')
        {
            switch (argv[i][1])
            {
                case 'k' :
                    generatekey();
                    break;
                case 'h' :
                    readkey(&pub, &prv);
                    test_homomorphic(pub, prv); 
                    gm_freepubkey(pub);
                    gm_freeprvkey(prv);
                    break;
                case 's' :
                    readkey(&pub, &prv);
                    test_longtext(pub, prv);
                    gm_freepubkey(pub);
                    gm_freeprvkey(prv);
                    break;
                default :
                    usage();
            }
        }
        else
        {
            usage();
        }
    }
    return 0;
}


