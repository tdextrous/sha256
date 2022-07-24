/**
 * sha256.c - Implementation of SHA-256 algorithm.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define WORD_MASK 0xFFFFFFFFU

uint32_t rotr(uint32_t n, uint32_t x) {
  return ((x >> n) | (x << (32-n))) & WORD_MASK;
}

uint32_t shr(uint32_t n, uint32_t x) {
  return (x >> n) & WORD_MASK;
}

uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
  return ((x & y) ^ (~x & z)) & WORD_MASK;
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
  return ((x & y) ^ (x & z) ^ (y & z)) & WORD_MASK;
}

uint32_t Sigma0(uint32_t x) {
  return (rotr(2, x) ^ rotr(13, x) ^ rotr(22, x));
}

uint32_t Sigma1(uint32_t x) {
  return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
}

uint32_t sigma0(uint32_t x) {
  return rotr(7, x) ^ rotr(18, x) ^ shr(3, x);
}

uint32_t sigma1(uint32_t x) {
  return rotr(17, x) ^ rotr(19, x) ^ shr(10, x);
}

/* SHA-256 constants */
uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

unsigned char* padmsg(unsigned char* M, uint64_t* len, uint64_t* newbitlen) {
  // find pad value
  int k = (448 - ((*len)*8+1)) % 512;

  // check for negative mod result.
  if (k < 0) {
    k += 512;
  }

  printf("K: %d\n", k);

  // convert length to 64 bit val.
  unsigned char lenbytes[8];
  for (int i = 0; i < 8; i++) {
    unsigned char tmp = (((*len)*8) >> (i*8)) & 0xFF;
    lenbytes[7-i] = tmp;
  }

  // create padded message byte array.
  *newbitlen = (*len)*8 + 1 + k + 64;
  unsigned char* paddedmsg = malloc((*newbitlen)/8 + 1);   // multiple of 512 + null byte.

  memcpy(paddedmsg, M, *len);                      // copy msg bytes
  memset(paddedmsg+*len, 0x80, 1);                 // set '1' byte.
  memset(paddedmsg+*len+1, 0, (k-7)/8);            // set 0 bytes.
  memcpy(paddedmsg+*len+((k+1)/8), lenbytes, 8);   // copy length value
  memset(paddedmsg+((*newbitlen)/8), '\0', 1);    // set null byte.

  return paddedmsg;
}

unsigned char** parse_msg_blocks(unsigned char* paddedmsg, uint64_t* numblks) {
  // Parse padded msg into 512 bit size blocks.
  unsigned char** msgblks = malloc(*numblks * (sizeof(unsigned char*)));
  for (int i = 0; i < *numblks; i++) {
    msgblks[i] = malloc(sizeof(unsigned char) * 64);
    memcpy(msgblks[i], paddedmsg + (i*64), 64);
  }
  return msgblks;
}

unsigned char** preprocess_msg(unsigned char* msg, uint64_t* msglen, uint64_t* numblks) {
  // Pad the message.
  uint64_t newbitlen;
  unsigned char* paddedmsg = padmsg(msg, msglen, &newbitlen);

  // Split message into blocks.
  *numblks = newbitlen / 512;
  unsigned char** msgblks = parse_msg_blocks(paddedmsg, numblks);

  // Free padded msg mem (unused).
  free(paddedmsg);

  return msgblks;
}

// Initial hash values.
uint32_t H0[] = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19
};

void printwords(uint32_t*, int);

uint32_t* sha256_compute(unsigned char** msgblks, uint64_t* numblks) {
  uint32_t* H = H0;
  uint32_t M[16];
  uint32_t W[64];  // TODO: OpenSSL can do SHA with length 16 message schedule. Implement that.
  uint32_t a, b, c, d, e, f, g, h, T1, T2;

  for (int i = 0; i < *numblks; i++) {
    // Get current message block
    for (int j = 0; j < 16; j++) {
      M[j] = (
          (msgblks[i][4*j] << 24) | 
          (msgblks[i][4*j+1] << 16) | 
          (msgblks[i][4*j+2] << 8) | 
          (msgblks[i][4*j+3])
      );
    }

    // Prepare message schedule.
    for (int t = 0; t < 64; t++) {
      if (t < 16) {
        W[t] = M[t];
      } else {
        W[t] = (sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]);
      }
    }

    printf("W[0-16]: ");
    printwords(W, 16);
    printf("\n");

    // Init working vars.
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    for (int t = 0; t < 64; t++) {
      T1 = (h + Sigma1(e) + ch(e,f,g) + K[t] + W[t]);
      T2 = (Sigma0(a) + maj(a,b,c));
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;

      printf("t=%02d ", t);
      printf("%04X ", a);
      printf("%04X ", b);
      printf("%04X ", c);
      printf("%04X ", d);
      printf("%04X ", e);
      printf("%04X ", f);
      printf("%04X ", g);
      printf("%04X ", h);
      printf("\n\n");
    }

    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];
  }

  // Concat final hash value.
  return H;
}

// Sha256 method closer to OpenSSL, use less memory for message schedule, combine loops.
uint32_t* sha256_compute_openssl(unsigned char** msgblks, uint64_t* numblks) {
  uint32_t* H = H0; // TODO: Should do deep copy.
  uint32_t W[16];  // Combined message schedule/initial array.
  uint32_t a, b, c, d, e, f, g, h, T1, T2;
  uint32_t s0, s1;

  int t;
  for (int i = 0; i < *numblks; i++) {
    // Fill message schedule with the current blk.
    unsigned char* currblk = msgblks[i];

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    for (t = 0; t < 16; t++) {
      W[t] = *(currblk++) << 24;
      W[t] |= *(currblk++) << 16;
      W[t] |= *(currblk++) << 8;
      W[t] |= *(currblk++);

      T1 = W[t] + h + Sigma1(e) + ch(e, f, g) + K[t];
      T2 = Sigma0(a) + maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    for (; t < 64; t++) {
      s0 = W[(t+1) & 0xf];
      s0 = sigma0(s0);
      s1 = W[(t + 14) & 0xf];
      s1 = sigma1(s1);

      T1 = W[t & 0xf] += s0 + s1 + W[(t + 9) & 0xf];
      T1 += h + Sigma1(e) + ch(e, f, g) + K[t];
      T2 = Sigma0(a) + maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
  }

  return H;
}

uint32_t* sha256(unsigned char* msg, uint64_t* msglen) {
  uint64_t numblks;
  unsigned char** msgblks = preprocess_msg(msg, msglen, &numblks);
  uint32_t* digest = sha256_compute(msgblks, &numblks);
  return digest;
}

uint32_t* sha256_openssl(unsigned char* msg, uint64_t* msglen) {
  uint64_t numblks;
  unsigned char** msgblks = preprocess_msg(msg, msglen, &numblks);
  uint32_t* digest = sha256_compute_openssl(msgblks, &numblks);
  return digest;
}

void printbytes(unsigned char* bytes, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02X", bytes[i]);
  }
}

void printwords(uint32_t* words, int len) {
  for (int i = 0; i < len; i++) {
    printf("%04X", words[i]);
  }
}

int main() {
  unsigned char* msg = (unsigned char*)"abc";
  //unsigned char* msg = (unsigned char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint64_t msgbytelen = strlen((char*)msg);

  uint64_t paddedbitlen;
  unsigned char* msg_pad = padmsg(msg, &msgbytelen, &paddedbitlen);
  uint64_t numblks = paddedbitlen / 512;
  unsigned char** msgblks = parse_msg_blocks(msg_pad, &numblks);

  printf("MSG (len=%lu):    ", msgbytelen);
  printbytes(msg, strlen((char*)msg));
  printf("\n");
  printf("PADMSG: ");
  printbytes(msg_pad, paddedbitlen/8);
  printf("\n");

  // Print msg blks.
  printf("BLKS (n=%lu)\n", numblks);
  for (int i = 0; i < numblks; i++) {
    printf("msgblks[%0d]: ", i);
    printbytes(msgblks[i], 64);
    printf("\n");
  }

  uint32_t* digest = sha256_openssl(msg, &msgbytelen);
  printf("digest: ");
  printwords(digest, 8);
  printf("\n");

  // Free memory
  free(msg_pad);
  for (int i = 0; i < numblks; i++) {
    free(msgblks[i]);
  }
  free(msgblks);

  return 0;
}
