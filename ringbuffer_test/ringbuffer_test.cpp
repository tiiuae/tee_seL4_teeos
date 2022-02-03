#include "gtest/gtest.h"
#include <vector>
#include <algorithm> 
#include <errno.h>
#include <thread>
#include <chrono>
#include <mutex>    

extern "C" {
#include "sel4_circ.h"
#include "ringbuffer.h"
}

namespace tst {
namespace ringbuffer {

class RingBufferTest : public ::testing::Test {
protected:

    RingBufferTest()
    {
        // CIRC buffer header
        memset(&circ_hdr, 0x0, sizeof(circ_hdr));
        circ.hdr = &circ_hdr;
        circ.hdr->buf_len = CIRC_BUF_LEN;

        // CIRC buffer
        mem_buffer.resize(CIRC_BUF_LEN, 0);
        circ.buf = mem_buffer.data();
    }

    void PrintBuffer()
    {
        std::cout << ::testing::PrintToString(mem_buffer) << std::endl;
    }

    void PrintCounters()
    {
        std::cout << "PrintCounters" << std::endl << "    head: " << circ.hdr->head << ", tail: " << circ.hdr->tail << std::endl;

        int cnt = CIRC_CNT(circ.hdr->head, circ.hdr->tail, CIRC_BUF_LEN);
        int cnt_end = CIRC_CNT_TO_END(circ.hdr->head, circ.hdr->tail, CIRC_BUF_LEN);
        int space = CIRC_SPACE(circ.hdr->head, circ.hdr->tail, CIRC_BUF_LEN);
        int space_end = CIRC_SPACE_TO_END(circ.hdr->head, circ.hdr->tail, CIRC_BUF_LEN);

        std::cout << "    cnt:        " << cnt << std::endl;
        std::cout << "    cnt_end:    " << cnt_end << std::endl;
        std::cout << "    space:      " << space << std::endl;
        std::cout << "    space_end:  " << space_end << std::endl;
    }

    void FillBufferFromStart(char data)
    {
        uint32_t loops = CIRC_BUF_LEN - 1;
        for (uint32_t i = 0; i < loops; i++) {
            int res = write_wrapper(&circ, 1, &data);
            ASSERT_EQ(res, 0) << "idx: " << i;
        }

        ASSERT_EQ(circ.hdr->head, loops);
    }

    void FillBufferFromStartInc()
    {
        std::vector<char> values(CIRC_BUF_LEN);
        int i = 1;
        std::generate(values.begin(), values.end(), [&](){ return i++; });

        int res = write_wrapper(&circ, CIRC_BUF_LEN - 1, values.data());
        ASSERT_EQ(res, 0);
        ASSERT_EQ(circ.hdr->head, CIRC_BUF_LEN - 1);
    }

    static constexpr uint32_t CIRC_BUF_LEN = (1 << 4); // 16

    std::vector<char> mem_buffer; /* only for buffer payload */
//    struct tee_comm_ctrl ctrl;
//    struct tee_comm_ch circ;

    volatile bool thread_stop = false;
    std::mutex print_mtx;

    struct circ_buf_hdr circ_hdr;
    struct circ_ctx circ;

public:
    void WriterFn()
    {
        constexpr ssize_t WRITE_LEN = 3;

        static constexpr uint32_t write_buf_len = WRITE_LEN;
        std::vector<char> write_val(write_buf_len);
        uint32_t wr_idx = 1;
        std::generate(write_val.begin(), write_val.end(), [&](){ return wr_idx++; });

        {
            std::lock_guard<std::mutex> lck (print_mtx);
            std::cout << "[WriterFn] write_val: " << write_val.size() << std::endl;
        }

        uint32_t wr_count = 0;
        uint32_t wait_count = 0;
        while(!thread_stop) {
            int res = write_wrapper(&circ, WRITE_LEN, write_val.data());
            if (res) {
                wait_count++;
                std::this_thread::yield();
                continue;
            }
            wr_count += WRITE_LEN;
            std::generate(write_val.begin(), write_val.end(), [&](){ return wr_idx++; });
        }

        {
            std::lock_guard<std::mutex> lck (print_mtx);
            std::cout << "[WriterFn] wr_idx:     " << wr_idx << std::endl;
            std::cout << "[WriterFn] wr_count:   " << wr_count << std::endl;
            std::cout << "[WriterFn] wait_count: " << wait_count << std::endl;
        }
    }

    void ReadFn()
    {
        static constexpr uint32_t READ_BUF_LEN = CIRC_BUF_LEN << 1;
        std::vector<char> read_buf(READ_BUF_LEN, 0);

        constexpr ssize_t READ_LEN = READ_BUF_LEN;

        {
            std::lock_guard<std::mutex> lck (print_mtx);
            std::cout << "[ReadFn] read_buf: " << read_buf.size() << std::endl;
        }

        uint32_t wr_idx = 1;

        uint32_t rcount = 0;
        uint32_t wait_count = 0;
        int32_t received = 0;
        ssize_t min_rec = 100000000;
        ssize_t max_rec = 0;

        while(!thread_stop) {
            int res = read_wrapper(&circ, READ_LEN, read_buf.data(), &received);
            if (res) {
                wait_count++;
                std::this_thread::yield();
                continue;
            }
            rcount += received;
            if (min_rec > received) min_rec = received;
            if (max_rec < received) max_rec = received;

            for (auto elem = read_buf.begin(); elem != read_buf.begin() + received; elem++) {
                char sh_idx = (char) wr_idx;
                if (*elem != sh_idx) {
                    FAIL() << "elem: " << int(*elem) << " sh_idx: " << int(sh_idx);
                }
                wr_idx++;
            }
        }

        {
            std::lock_guard<std::mutex> lck (print_mtx);
            std::cout << "[ReadFn] rcount:       " << rcount << std::endl;
            std::cout << "[ReadFn] wait_count:   " << wait_count << std::endl;
            std::cout << "[ReadFn] min_rec:      " << min_rec << std::endl;
            std::cout << "[ReadFn] max_rec:      " << max_rec << std::endl;
            std::cout << "[ReadFn] wr_idx:       " << wr_idx << std::endl;
        }

    }
};

TEST_F(RingBufferTest, TestBufferLengthPowerOf2) 
{
    uint32_t len = CIRC_BUF_LEN;

    while (true) {
        if (len & 0x1) {
            break;
        }
        len >>= 1;
    }

    ASSERT_EQ(len, 1);
}

TEST_F(RingBufferTest, WriteSingleItem) 
{
    int32_t res = 0;

    char data = 5;

    // Fill buffer
    FillBufferFromStart(data);

    int head = circ.hdr->head;

    // Buffer full, adding more data fails
    res = write_wrapper(&circ, 1, &data);
    ASSERT_NE(res, 0);

    // Head stays the same
    ASSERT_EQ(circ.hdr->head, head);

    {
        std::vector<char> result = {
            data, /* 00 */
            data, /* 01 */
            data, /* 02 */
            data, /* 03 */
            data, /* 04 */
            data, /* 05 */
            data, /* 06 */
            data, /* 07 */
            data, /* 08 */
            data, /* 09 */
            data, /* 10 */
            data, /* 11 */
            data, /* 12 */
            data, /* 13 */
            data, /* 14 */
            0,    /* 15 */
        };

        ASSERT_EQ(mem_buffer, result);
    }
}

TEST_F(RingBufferTest, WriteWithArray) 
{
    int32_t res = 0;

    std::vector<char> data_in = {1,2,3,4,5,6};

    res = write_wrapper(&circ, data_in.size(), data_in.data());
    ASSERT_EQ(res, 0);

    ASSERT_EQ(circ.hdr->head, data_in.size());

    {
        std::vector<char> result = {
            1, /* 00 */
            2, /* 01 */
            3, /* 02 */
            4, /* 03 */
            5, /* 04 */
            6, /* 05 */
            0, /* 06 */
            0, /* 07 */
            0, /* 08 */
            0, /* 09 */
            0, /* 10 */
            0, /* 11 */
            0, /* 12 */
            0, /* 13 */
            0, /* 14 */
            0, /* 15 */
        };

        ASSERT_EQ(mem_buffer, result);
    }

    res = write_wrapper(&circ, data_in.size(), data_in.data());
    ASSERT_EQ(res, 0);

    ASSERT_EQ(circ.hdr->head, data_in.size() * 2);

    {
        std::vector<char> result = {
            1, /* 00 */
            2, /* 01 */
            3, /* 02 */
            4, /* 03 */
            5, /* 04 */
            6, /* 05 */
            1, /* 06 */
            2, /* 07 */
            3, /* 08 */
            4, /* 09 */
            5, /* 10 */
            6, /* 11 */
            0, /* 12 */
            0, /* 13 */
            0, /* 14 */
            0, /* 15 */
        };

        ASSERT_EQ(mem_buffer, result);
    }

    // Write fails as there's not enough room in buffer
    res = write_wrapper(&circ, data_in.size(), data_in.data());
    ASSERT_NE(res, 0);

    // Fill the remaining buffer
    res = write_wrapper(&circ, 3, data_in.data());
    ASSERT_EQ(res, 0);

    ASSERT_EQ(circ.hdr->head, CIRC_BUF_LEN - 1);

    {
        std::vector<char> result = {
            1, /* 00 */
            2, /* 01 */
            3, /* 02 */
            4, /* 03 */
            5, /* 04 */
            6, /* 05 */
            1, /* 06 */
            2, /* 07 */
            3, /* 08 */
            4, /* 09 */
            5, /* 10 */
            6, /* 11 */
            1, /* 12 */
            2, /* 13 */
            3, /* 14 */
            0, /* 15 */
        };

        ASSERT_EQ(mem_buffer, result);
    }
}

TEST_F(RingBufferTest, WriteBufferOverflow) 
{
    int32_t res = 0;

    std::vector<char> data_in(CIRC_BUF_LEN + 5, 5);

    // Try to write more than buffer length
    res = write_wrapper(&circ, data_in.size(), data_in.data());
    ASSERT_NE(res, 0);

    ASSERT_EQ(circ.hdr->head, 0);
}

TEST_F(RingBufferTest, WriteZeroBytes) 
{
    int32_t res = 0;

    std::vector<char> data_in(CIRC_BUF_LEN, 5);

    // Write zero bytes
    res = write_wrapper(&circ, 0, data_in.data());
    ASSERT_EQ(res, 0);

    ASSERT_EQ(circ.hdr->head, 0);

    // No actual writes
    std::vector<char> result(CIRC_BUF_LEN, 0);
    ASSERT_EQ(mem_buffer, result);
}

TEST_F(RingBufferTest, ReadSingleItem) 
{
    int32_t res = 0;

    char data = 5;
    char read_init = 9;

    std::vector<char> read_buffer(CIRC_BUF_LEN, read_init);
    int32_t received = 0;

    // Fill buffer
    FillBufferFromStart(data);

    res = read_wrapper(&circ, 1, read_buffer.data(), &received);
    ASSERT_EQ(res, 0);

    ASSERT_EQ(received, 1);
    ASSERT_EQ(circ.hdr->tail, 1);

    {
        std::vector<char> result = {
            data,         /* 00 */
            read_init,    /* 01 */
            read_init,    /* 02 */
            read_init,    /* 03 */
            read_init,    /* 04 */
            read_init,    /* 05 */
            read_init,    /* 06 */
            read_init,    /* 07 */
            read_init,    /* 08 */
            read_init,    /* 09 */
            read_init,    /* 10 */
            read_init,    /* 11 */
            read_init,    /* 12 */
            read_init,    /* 13 */
            read_init,    /* 14 */
            read_init,    /* 15 */
        };
        ASSERT_EQ(read_buffer, result);
    }

    for (uint32_t i = 0; i < CIRC_BUF_LEN - 2; i++) {
        res = read_wrapper(&circ, 1, read_buffer.data() + i + 1, &received);
        ASSERT_EQ(received, 1);
        ASSERT_EQ(res, 0) << "idx: " << i;
    }

    ASSERT_EQ(circ.hdr->tail, 15);

    // This read should fail
    char single_char = 0;
    res = read_wrapper(&circ, 1, &single_char, &received);
    ASSERT_NE(res, 0);

    ASSERT_EQ(received, 0);
    ASSERT_EQ(circ.hdr->tail, 15);

    {
        std::vector<char> result = {
            data,       /* 00 */
            data,       /* 01 */
            data,       /* 02 */
            data,       /* 03 */
            data,       /* 04 */
            data,       /* 05 */
            data,       /* 06 */
            data,       /* 07 */
            data,       /* 08 */
            data,       /* 09 */
            data,       /* 10 */
            data,       /* 11 */
            data,       /* 12 */
            data,       /* 13 */
            data,       /* 14 */
            read_init,  /* 15 */
        };
        ASSERT_EQ(read_buffer, result);
    }
}

TEST_F(RingBufferTest, ReadChunks) 
{
    int32_t res = 0;
    char read_init = 0xFF;
    std::vector<char> read_buffer(CIRC_BUF_LEN, read_init);
    int32_t received = 0;

    FillBufferFromStartInc();

    // Read multiple items from buffer
    int32_t read_count = 6;
    res = read_wrapper(&circ, read_count, read_buffer.data(), &received);
    ASSERT_EQ(res, 0);

    ASSERT_EQ(received, read_count);
    ASSERT_EQ(circ.hdr->tail, read_count);

    {
        std::vector<char> result = {
            1,          /* 00 */
            2,          /* 01 */
            3,          /* 02 */
            4,          /* 03 */
            5,          /* 04 */
            6,          /* 05 */
            read_init,  /* 06 */
            read_init,  /* 07 */
            read_init,  /* 08 */
            read_init,  /* 09 */
            read_init,  /* 10 */
            read_init,  /* 11 */
            read_init,  /* 12 */
            read_init,  /* 13 */
            read_init,  /* 14 */
            read_init,  /* 15 */
        };

        ASSERT_EQ(read_buffer, result);
    }

    // Second time same amount
    res = read_wrapper(&circ, read_count, read_buffer.data() + read_count, &received);
    ASSERT_EQ(res, 0);

    ASSERT_EQ(received, read_count);
    ASSERT_EQ(circ.hdr->tail, read_count * 2);

    {
        std::vector<char> result = {
            1,          /* 00 */
            2,          /* 01 */
            3,          /* 02 */
            4,          /* 03 */
            5,          /* 04 */
            6,          /* 05 */
            7,          /* 06 */
            8,          /* 07 */
            9,          /* 08 */
            10,         /* 09 */
            11,         /* 10 */
            12,         /* 11 */
            read_init,  /* 12 */
            read_init,  /* 13 */
            read_init,  /* 14 */
            read_init,  /* 15 */
        };

        ASSERT_EQ(read_buffer, result);
    }

    // Third try. Should return rest of buffer content.
    res = read_wrapper(&circ, read_count, read_buffer.data() + (read_count * 2), &received);
    ASSERT_EQ(res, 0);

    ASSERT_EQ(received, 3);
    ASSERT_EQ(circ.hdr->tail, 15);

    {
        std::vector<char> result = {
            1,          /* 00 */
            2,          /* 01 */
            3,          /* 02 */
            4,          /* 03 */
            5,          /* 04 */
            6,          /* 05 */
            7,          /* 06 */
            8,          /* 07 */
            9,          /* 08 */
            10,         /* 09 */
            11,         /* 10 */
            12,         /* 11 */
            13,         /* 12 */
            14,         /* 13 */
            15,         /* 14 */
            read_init,  /* 15 */
        };

        ASSERT_EQ(read_buffer, result);
    }

}

TEST_F(RingBufferTest, ReadEmptyBuffer) 
{
    int32_t res = 0;

    char data = 0;
    int32_t received = 0;

    // circ buffer is empty
    res = read_wrapper(&circ, 1, &data, &received);
    ASSERT_NE(res, 0);

    ASSERT_EQ(received, 0);
    ASSERT_EQ(circ.hdr->tail, 0);
}

TEST_F(RingBufferTest, ReadZeroBytes) 
{
    int32_t res = 0;

    char data = 9;
    int32_t received = 0;

    FillBufferFromStartInc();

    res = read_wrapper(&circ, 0, &data, &received);
    ASSERT_NE(res, 0);

    ASSERT_EQ(received, 0);
    ASSERT_EQ(circ.hdr->tail, 0);

    ASSERT_EQ(data, 9);
}

TEST_F(RingBufferTest, WriteReadWrap) 
{
    int32_t res = 0;

    std::vector<char> gen_val(CIRC_BUF_LEN * 2);
    int idx = 1;
    std::generate(gen_val.begin(), gen_val.end(), [&](){ return idx++; });
    int32_t write_count = 0;

    std::vector<char> read_buffer(CIRC_BUF_LEN, 0);
    int32_t received = 0;
    int32_t read_count = 0;

    // Fill buffer
    res = write_wrapper(&circ, CIRC_BUF_LEN - 1, gen_val.data());
    ASSERT_EQ(res, 0);

    ASSERT_EQ(circ.hdr->head, 15);
    ASSERT_EQ(circ.hdr->tail, 0);
    // CIRC_BUF = {
    //     1,  /* 00 */ <- tail
    //     2,  /* 01 */
    //     3,  /* 02 */
    //     4,  /* 03 */
    //     5,  /* 04 */
    //     6,  /* 05 */
    //     7,  /* 06 */
    //     8,  /* 07 */
    //     9,  /* 08 */
    //     10, /* 09 */
    //     11, /* 10 */
    //     12, /* 11 */
    //     13, /* 12 */
    //     14, /* 13 */
    //     15, /* 14 */
    //     0,  /* 15 */ <- head
    // };

    // Free some space from buffer
    read_count = 3;
    res = read_wrapper(&circ, read_count, read_buffer.data(), &received);
    ASSERT_EQ(res, 0);

    ASSERT_EQ(circ.hdr->head, 15);
    ASSERT_EQ(circ.hdr->tail, 3);
    // CIRC_BUF = {
    //     1,  /* 00 */
    //     2,  /* 01 */
    //     3,  /* 02 */
    //     4,  /* 03 */ <- tail
    //     5,  /* 04 */
    //     6,  /* 05 */
    //     7,  /* 06 */
    //     8,  /* 07 */
    //     9,  /* 08 */
    //     10, /* 09 */
    //     11, /* 10 */
    //     12, /* 11 */
    //     13, /* 12 */
    //     14, /* 13 */
    //     15, /* 14 */
    //     0,  /* 15 */ <- head
    // };

    // Write more data: 2 bytes written to the beginning of buffer
    write_count = 3;
    res = write_wrapper(&circ, write_count, gen_val.data() + (CIRC_BUF_LEN - 1));
    ASSERT_EQ(res, 0);

    ASSERT_EQ(circ.hdr->head, 2);
    ASSERT_EQ(circ.hdr->tail, 3);
    // CIRC_BUF = {
    //     17,  /* 00 */ write [1]
    //     18,  /* 01 */ write [2]
    //     3,   /* 02 */ <- head
    //     4,   /* 03 */ <- tail
    //     5,   /* 04 */
    //     6,   /* 05 */
    //     7,   /* 06 */
    //     8,   /* 07 */
    //     9,   /* 08 */
    //     10,  /* 09 */
    //     11,  /* 10 */
    //     12,  /* 11 */
    //     13,  /* 12 */
    //     14,  /* 13 */
    //     15,  /* 14 */
    //     16,  /* 15 */ write [0]
    // };

    {
        std::vector<char> result = {
            17, /* 00 */
            18, /* 01 */
            3,  /* 02 */
            4,  /* 03 */
            5,  /* 04 */
            6,  /* 05 */
            7,  /* 06 */
            8,  /* 07 */
            9,  /* 08 */
            10, /* 09 */
            11, /* 10 */
            12, /* 11 */
            13, /* 12 */
            14, /* 13 */
            15, /* 14 */
            16, /* 15 */
        };

        ASSERT_EQ(mem_buffer, result);
    }

    // Read all available data
    read_count = 15;
    res = read_wrapper(&circ, read_count, read_buffer.data(), &received);
    ASSERT_EQ(res, 0);
    ASSERT_EQ(received, read_count);

    ASSERT_EQ(circ.hdr->head, 2);
    ASSERT_EQ(circ.hdr->tail, 2);
    // CIRC_BUF = {
    //     17,  /* 00 */
    //     18,  /* 01 */
    //     3,   /* 02 */ <- head <- tail
    //     4,   /* 03 */
    //     5,   /* 04 */
    //     6,   /* 05 */
    //     7,   /* 06 */
    //     8,   /* 07 */
    //     9,   /* 08 */
    //     10,  /* 09 */
    //     11,  /* 10 */
    //     12,  /* 11 */
    //     13,  /* 12 */
    //     14,  /* 13 */
    //     15,  /* 14 */
    //     16,  /* 15 */
    // };

    {
        // Tail is already located in buf[3] == 4, when last read is done.
        std::vector<char> result = {
            4,  /* 00 */
            5,  /* 01 */
            6,  /* 02 */
            7,  /* 03 */
            8,  /* 04 */
            9,  /* 05 */
            10, /* 06 */
            11, /* 07 */
            12, /* 08 */
            13, /* 09 */
            14, /* 10 */
            15, /* 11 */
            16, /* 12 */
            17, /* 13 */
            18, /* 14 */
            0,  /* 15 */
        };

        ASSERT_EQ(read_buffer, result);
    }

}

TEST_F(RingBufferTest, Thread1) 
{
    std::thread th1 (&RingBufferTest::WriterFn, this);
    std::thread th2 (&RingBufferTest::ReadFn, this);

    std::this_thread::sleep_for (std::chrono::seconds(4));
    thread_stop = true;

    th1.join();
    th2.join();
    PrintCounters();

}

} // namespace ringbuffer
} // namespace tst
