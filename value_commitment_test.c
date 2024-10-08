#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <secp256k1.h>
#include "./include/secp256k1_generator.h"
#include "./include/secp256k1_rangeproof.h"


#ifndef SECP256K1_CONTEXT_ALL
#define SECP256K1_CONTEXT_ALL SECP256K1_CONTEXT_NONE | SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
#endif


void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Function to convert a hexadecimal string to a byte array
void hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

// Function to convert a byte array to a hexadecimal string
void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex) {
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(&hex[i * 2], "%02x", bytes[i]);
    }
}

// Function to print a point
void print_point(const secp256k1_context *ctx, const secp256k1_pubkey *pubkey, const char *label) {
    unsigned char pubkey_bytes[33];
    size_t output_length = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &output_length, pubkey, SECP256K1_EC_COMPRESSED);
    char pubkey_hex[67];
    bytes_to_hex(pubkey_bytes, 33, pubkey_hex);
    printf("%s (hex): %s\n", label, pubkey_hex);
}

// Convert a 64-bit integer to a 32-byte array
void uint64_to_bytes(uint64_t value, unsigned char *bytes) {
    memset(bytes, 0, 32);  // Initialize the byte array to zero
    for (int i = 0; i < 8; i++) {
        bytes[31 - i] = (unsigned char)(value >> (8 * i));
    }
}


// Function to print a scalar
void print_scalar(const unsigned char *scalar, const char *label) {
    char scalar_hex[65];
    bytes_to_hex(scalar, 32, scalar_hex);
    printf("%s: %s\n", label, scalar_hex);
}

void rangeproof() {
    unsigned char value_bytes[32];
    unsigned char script[23];
    unsigned char msg[64];
    unsigned char nonce[32];
    unsigned char assetCommitment[33];
    unsigned char valueCommitment[33];
    unsigned char valueBlinder[32];
    unsigned char expected[2893];

    uint64_t value = strtoull("123455000", NULL, 10);
    uint64_to_bytes(value, value_bytes);

    int minval = 1;
    int exp = 0;
    int bits = 36;

    hex_to_bytes("0953c4bf412d07fad5e05fe0f5ea2107a546f9cfef38ef2b962ffd84a89de03d7f", valueCommitment, 33);
    hex_to_bytes("0a8d276fa2ab45fed0f622f818be77f456baa2f3b90456e30d2c561446b25b5458", assetCommitment, 33);
    hex_to_bytes("de22de5f5fe49cc6ac2bb8952567151c7c36b42e2e2f2aa587d4ed2060b2ba4d", valueBlinder, 32);
    hex_to_bytes("f295f2c7a42274f8f90a9d7f8649d78b67e693703246bf6086653c8646a363f5", nonce, 32);
    hex_to_bytes("a914d7da691a2b7256aa3bce759ef2b8ff5213fa327987", script, 23);
    hex_to_bytes("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95ac4681a2583b714a31c5a0b997a6c107a96be4aef4847d9cde3035e8ef23642bf", msg, 64);
    hex_to_bytes("60230000000000000001a33701f0954c84cd6f383a536677e4279108eed11f62d2a5b1e3f15c622c850c0ad11fda43884cf1a0b356adddc9027b0ae6fb5ff044cd0494d863c0edf46a22306e3793062df327e14382a45c7a78a6ba60eb54938d891fd7816fda940332d67484b3b9c153501f84a175d756f109272cf03333ee2c9351d01c6762d797e0ba0a9e84881fcc79dafb887c5bcc244bc0f23e8aee40cfbeaf4df937bc4ab04874769a39a7f364b5f7b824c4cbdfab1240efe46d58b9057f14a459575825eb526184181803f05ba3e369b9d4084e2754faf1813db09f8120f3c871a3fbf35ee31f6027980fdfa80758b564b7501384bd5e1af005f76e6f1e388a25c02ddc290a97fe2d05b744d0ff5107a6912c4a766c3485eafd8c04c6cc99283adea66d8b8c88a124a296a78ac10b3a82ec3ff6eca5b7b330d56ed59ebd003bbde7915dedb5794c506320f9172e58b58082aa20b5bcbf2ed57a9d0f1bd5ecf8bed80392731cd82176c45457077e96b4a4a992975feccd2c8ce2e423e85b5455561e2d31a6c68b17f2abaddbff1a065da052bb83327966a96dc3f252b0c3f91868d30cb1f0d90b75a194bdf96058158897d596941d5675f5b9de37f3e9243f454611dad3acee6cbceb1a5ac1ef0b03f8b512166cdf8386d5492e7b591f5b3daf33658a6f2c4f9a028d0883f1349f73a28ebc1630165e500d59503c1ca4c203ee53b881eb42c2d8097f806183ce2628247485d85d87b113d1309d26332ffb734355b17cfe41c1f82fbd6da5ebba7c91664a2f7be6863e9eccbb2b925d8b0451bc2333f860d21e18c1d0713c7eb2d4f120236cb0dfe3945b696be77c47cf1a29e235c35804f23ff1ac8525a60a040d5f0780eda7b71fe2d956ccaa5dd7f9fe4db310e46fa19f0b493f7a90a66afd71fc5e84b9f39c814ecbc0605bb3b0efb78424846d0f1b831bbccd8e0fd4fc0f4aeafe4893208cd84ebc75f5619f9af9e0f68adc0484b71b23018bbeefcd6e071a6de624f16c92328177ee48e8e35445b5b330aed000daa2f4ebe5c17e8532b9c5a0ab4a477c1cdc32e0125506d159816011cf581924ef9b138cdca8232384a600c39a57b71044fee0d976022e376fcdc2d83544330e5bc94384d089de45c1872f40a3961e8fd6f4cbf3ac131a44688a7214c15325ba89ac7a55aa87904f6f33828e1f432bb8f0f040d8403c87300a7ac0a146dd87af4f1aff96f428f4dbb1dd35538b44b0de4076793b2f1c70cc5d3916d6bd70e770bd891f8461a27a839bb1efdef78234c6d07c75891e9a0a9dfd9f2de5cdd4a6b898dad80254afb6ae9d763bc3860e0b19ae7de55a27d935576e8b7575846d2befd251d8d4b0f62b3f78436439ffab4cb4edc663d58c053474f3631d98cddcae7c9342cbac6bc2e52f103749933db21486130a56be1bcaee78137ef8306dc5bec2b3afe9afcc4344d4aca0e4f173d503583872141f4da19a45aa2b0f2fb1a15dc3d9e2f6a189948eee285da37968cc35b34c93db92421003893ff6aca7c90c89d46b771669cd43ae3f4d4a2e047183bc15ae38cac485b7ea050150013547506b3fffb38ca9f4f433624aedf0ee54feb5e140225116e869fe1d3c5e45c0564d130fa1a6b13191ed592a9bf0c49198db1a62d1a6da7ed7cd3027937c4f8817888678514b1c503f013c98bd230af3a180ebe57f559632cb65a0dc806fd34b6f2d57da6e385207cfb90368f5efbaa6fc7a118e6b8805628321bef76db29aafc4edf9c76a10f66bf18fd8b3cac4c9ef23574272d4b89f055d2cd1f5759d027b93301c7b3bbe7cd137c9dca5fa59141dc32bddb9c6167a01a612413b3c2d830c3d0d4c1631994556180c5fba28ee3780875cfb43525b1cc586901aa6b933be18d514975f84ca40ba0806866d48b62419ccb92f97a67538387529959de7df9b5760a11d669a666f7d0694263dbd798d1faaf31e6f6c3ec7e374132475d2fc05d29e5b7b43d8d8f342a715208ce598893efae6991d1b49c94687e31a0b8749740b70e58e4d0ccb053ab0d8cd470f9ad08fe66ea91c3d1b56ccc6f2d98d054783d5bc7c57b9660cd316a61485e96be30379537859a58021734e4b4357c3a196a17e089299cd22023cfa3e7b2508ee70b904fea821df6edd03d8fdaccf4b4560388c00681c47b9462697897a461f4247ab69207a9e1316781daf3eb32a22bdd60dc7b9f9e3bff087e137a65714abcfd47f493b9cdb1f844e7f117499150a8a3d5380c982d65e42a4366f683ef4dfd7f8de1289e30c3cd531afeabac4202541ca7dae26877fd2e184a9911e0cf295be51d2febcedcfce480abcf7ce1bf7e4c0a311ab9542f4869e3e78b5638a07fe304f14d2aa7ca1577ca87bfc8e6de0ee8f6f2c10223bcc51eb13b2683373adf10cd50098848c1e7640831db154c63c55655f610c03dbc83d7e761003d8ffb9e5012ffcff45b70917abcd429aa7d1c432ef7e0be417c989a59a3264edc2a731fe9ed0b2296cfaf2c27f5b225b018f190c6d37f177427875bf362c8197e5c984ad483142310e351e42697339305bc9885a9d9da9a16b96a9a72d279f2b1be829dfa81312edd35d125580e55b82fe6a99688bd7ac2082d33cac20b1f5ca5b52b12ba1846ff4c942b04fae07a0b12d61449ed750cc366e865dc28a96a75761e82409fd055d24410228d1599ec5781c33eb6f0cea57a7982e13adeb81d2a0f6e052895e4b81c17656452caa74709191029ce41c962f3d8619d67445ab3debe5c75e6c128d618b9b98f1808a2b88a004996daa07d16e616ab1d6a1af563c3779a08a2f0dd2c9574ff7843907a20474d2ca34b1bddc999dad355a28178ed6c0f254cebbd64e8ba30f11394d40a6bbe63aed53ed3d08a1a561801857e8648fe8621c34ce3230dc498ccf189e596e50fef40f975f8be9369da5abc372f367c84e0844d732c761cd192dd9f83cf8e5470b5b13d5c480354a9cc03f1e96799cb1d5cc9ea380dd99e14d2c66bc735899562d74666b2d2e1515d4b50fb3c1b40530d2d3d38991be8e03305ef3d54111642614f24106658bcf0ee766085fc74b5199f15584defaeab8d22a0b05d352d3762a55a86d056b8b0006bff5d94ace6fab9bb10049fe4128852a4190a9cc42a7a89a5bf191b776e2cf39f784d21d3fa9d4cd7e2328c81f292743977c36202088586ba7db1b7295eeb2ab76d2c31d87bb3acc10a44a39b67565ab4320951a7969d3ab50fbef9215c162fb4b5260ea70e34ec023494334af968ebe3f27b7ffd5c44b5a4eeb62aa8bd530fa3b87412c8f635e116f9c05ce66ad0b735e84af5078be9d9efd41037c593fda7d58b73a7080fc6151fc3ba5b0ca175b3da4e8b602735ebe7a6c2b82fa5903604917eb84542679c90a0151dfa3f6cad01ca89e92ff57f7707c54d1c6550e0686122cbdb16bc2983002c55aa23f659945af8b0cf8c37838d7607aa1215a0e2fbc3f403489902141245966007a800f3686558e565a67c9f51dfa878450e3abee41c1fe5ffa57a37eebbb657bce26ca32bfcd7a4c587ba65a15d9280cbd50acfbc876d3f062eed1099c6519e84a303805a38547846ba9490b1eaa7da50db123a1ff201b272309f9442f22630aeeaf46950f2fc825403eb337b8737677f5afcd822cb137a547d203015a0e7455bda60b93676852484647f0d49d57b8e7c8eabdb7a736585b501001114b4e2cf304f073e543420410ed180adbf5a87e1c11b332a08e29a93241c17532c880e493b14c644cbb3eb45843c7bae6ab436cadbfedc3da860da7092301b05055569ce3ba6c3425cf295845366554c0e4108188a0441326923d69777ae9761c99ed6a78782fa15c1c2d708a4fde61fdc8cff4e1534eacc15229041415a19d89c975294558f4abcc5de2d7231ee7b5e0ef7ba1ffb3c2f8891e24002d14254d81db63fc804a1037e808816573f7c73b3f225d09b29e03fe9ae9f79c40e69eb466fc3cafc5cdc0450b46d575fdee83001a755b61fe4e4cd98fa880ebd4b6f3904716ac3a619a42e1800c7360563410f703163e2b8975cd8d272f58768ebed263ee8a8381054d81", expected, 2893);


    unsigned char proof[5134];
    size_t plen = 5134;
    size_t msglen = sizeof(msg) / sizeof(msg[0]);
    size_t scriptlen = sizeof(script) / sizeof(script[0]);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);

    secp256k1_pedersen_commitment commit;
    int ret = secp256k1_pedersen_commitment_parse(ctx, &commit, valueCommitment);
    if (!ret)
    {
      secp256k1_context_destroy(ctx);
      return;
    }

    secp256k1_generator gen;
    ret = secp256k1_generator_parse(ctx, &gen, assetCommitment);
    if (!ret)
    {
      secp256k1_context_destroy(ctx);
      return;
    }

    ret = secp256k1_rangeproof_sign(
        ctx,
        proof,
        &plen,
        minval,
        &commit,
        valueBlinder,
        nonce,
        exp,
        bits,
        value,
        msg,
        msglen,
        script,
        scriptlen,
        &gen
      );


    // print_hex(proof, plen);

    // Compare the created commitment with the expected commitment
    if (ret && memcmp(proof, expected, plen) == 0) {
        printf("Rangeproof matches expected proof.\n");
    } else {
        printf("Rangeproof does not match expected proof.\n");
    }

    return;
}

int main() {
    rangeproof();
    return 0;
}

