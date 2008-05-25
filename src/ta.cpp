#include <botan/ta.h>

unsigned cyc_hi = 0;
unsigned cyc_lo = 0;
long unsigned int last_cycles = 0;
long unsigned int montgm_red = 0;
long unsigned int montgm_mult = 0;

unsigned int nov_ecdsa_div_words_inner = 0;
unsigned int nov_ecdsa_div_words_outer = 0;
long unsigned int nov_ecdsa_last_cycles = 0;

unsigned int ta_mm_red_bloat = 0;
