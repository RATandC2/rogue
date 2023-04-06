#include "Common.h"

D_SEC( B ) void arc4_swap(struct arc4_context* ctx, size_t i, size_t j)
{
    uint8_t const t = ctx->s[i];
    ctx->s[i] = ctx->s[j];
    ctx->s[j] = t;
}

D_SEC( B ) uint8_t arc4_next(struct arc4_context* ctx)
{
    ctx->i += 1;
    ctx->j += ctx->s[ctx->i];

    arc4_swap(ctx, ctx->i, ctx->j);

    return ctx->s[(uint8_t)(ctx->s[ctx->i] + ctx->s[ctx->j])];
}

D_SEC( B ) void arc4_init(struct arc4_context* ctx, void const* key, size_t key_length)
{
    ctx->i = 0;
    ctx->j = 0;

    for (size_t i = 0; i < 256; ++i)
    {
        ctx->s[i] = (uint8_t)i;
    }

    for (size_t i = 0, j = 0; i < 256; ++i)
    {
        j = (uint8_t)(j + ctx->s[i] + ((uint8_t const*)key)[i % key_length]);
        arc4_swap(ctx, i, j);
    }
}

D_SEC( B ) void arc4_process(struct arc4_context* ctx, void const* src_data, void* dst_data, size_t data_length)
{
    if (data_length == 0)
    {
        return;
    }

    for (size_t i = 0; i < data_length; ++i)
    {
        ((uint8_t*)dst_data)[i] = ((uint8_t const*)src_data)[i] ^ arc4_next(ctx);
    }
}

D_SEC( B ) void arc4_discard(struct arc4_context* ctx, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        arc4_next(ctx);
    }
}
