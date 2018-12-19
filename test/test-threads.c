#include <pthread.h>

void trace(void)
{
    /* nop */
}

void* thread_func(void *opaque)
{
    trace();
}

void main(void)
{
    pthread_t threads[NUM_THREADS];
    int t;

    for (t = 0; t < NUM_THREADS; t++) {
        pthread_create(&threads[t], NULL, thread_func, NULL);
    }

    for (t = 0; t < NUM_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }
}
