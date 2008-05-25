#ifndef TA_H_
#define TA_H_

#include <stdio.h>
extern unsigned cyc_hi;
extern unsigned cyc_lo;
extern long unsigned int last_cycles;
extern long unsigned int montgm_red;
extern long unsigned int montgm_mult;

extern unsigned int nov_ecdsa_div_words_inner;
extern unsigned int nov_ecdsa_div_words_outer;
extern long unsigned int nov_ecdsa_last_cycles;

extern unsigned int ta_mm_red_bloat;

/*
inline long unsigned int get_last_cycles()
{
    return last_cycles;
}

inline void serialize()
{
    // call the serializing cpuid instruction
    // where we have to save and restore %ebx
    // which is a callee save register
    int tmp_ebx;
    asm(" movl %%ebx %1;cpuid; movl %0 %%ebx"  // input/ output correct?
    : "=r" (tmp_ebx) // output
    : "r" (tmp_ebx) // input
    : "%eax", "%ecx", "%edx");
}

inline void access_counter(unsigned *hi, unsigned *lo)
{
    //serialize();

    asm("rdtsc; movl %%edx,%0; movl %%eax,%1"
    : "=r" (*hi), "=r" (*lo)
    : // No input
    : "%edx", "%eax");
}
inline void start_counter()
{
    access_counter(&cyc_hi, &cyc_lo);
}
//double get_counter()
inline long long unsigned int get_counter()
{
    unsigned ncyc_hi, ncyc_lo;
    unsigned hi, lo, borrow;
    long long unsigned int result;
    //double result;

    access_counter(&ncyc_hi, &ncyc_lo);
    lo = ncyc_lo - cyc_lo;
    borrow = lo > ncyc_lo;
    hi = ncyc_hi - cyc_hi - borrow;
//    cout << "hi = " << hi << endl;
//    cout << "lo = " << lo << endl;
    //result = (double) hi * (1 << 30) * 4 + lo;
    result = (long long unsigned int) hi * (1 << 30) * 4 + lo;
//    cout << "result = " << result << endl;
//    if (result < 0) // doesn´t test anything
//    {
//        fprintf(stderr, "Error: counter returns negative value: %.0f\n", result);
//    }
    return result;
}

class TA_Counter
{
    private:
        unsigned m_cyc_hi;
        unsigned m_cyc_lo;
        long unsigned int m_last_cycles;
        //extern long unsigned int m_montgm_red;
        //extern long unsigned int m_montgm_mult;
        inline long unsigned int m_get_last_cycles()
        {
            return m_last_cycles;
        }

        inline void serialize()
        {
    // call the serializing cpuid instruction
    // where we have to save and restore %ebx
    // which is a callee save register
            int tmp_ebx;
            asm(" movl %%ebx %1;cpuid; movl %0 %%ebx"  // input/ output correct?
                : "=r" (tmp_ebx) // output
                : "r" (tmp_ebx) // input
                : "%eax", "%ecx", "%edx");
        }
    public:
        inline void access_counter(unsigned *hi, unsigned *lo)
        {
    //serialize();

            asm("rdtsc; movl %%edx,%0; movl %%eax,%1"
                : "=r" (*hi), "=r" (*lo)
                : // No input
                : "%edx", "%eax");
        }
        inline void start_counter()
        {
            access_counter(&m_cyc_hi, &m_cyc_lo);
        }
//double get_counter()
        inline long unsigned int get_counter()
        {
            unsigned ncyc_hi, ncyc_lo;
            unsigned hi, lo, borrow;
            long unsigned int result;
    //double result;

            access_counter(&ncyc_hi, &ncyc_lo);
            lo = ncyc_lo - m_cyc_lo;
            borrow = lo > ncyc_lo;
            hi = ncyc_hi - m_cyc_hi - borrow;
//    cout << "hi = " << hi << endl;
//    cout << "lo = " << lo << endl;
    //result = (double) hi * (1 << 30) * 4 + lo;
            result = (long unsigned int) hi * (1 << 30) * 4 + lo;
//    cout << "result = " << result << endl;
    //if (result < 0) // doesn´t test anything
      //      {
        //    fprintf(stderr, "Error: counter returns negative value: %.0f\n", result);
        //}
            return result;
        }

};*/

#endif /*TA_H_*/
