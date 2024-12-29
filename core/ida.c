// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ID allocator
 */

#include <cpu.h>
#include <ida.h>
#include <defs.h>
#include <errno.h>
#include <stdint.h>
#include <printk.h>
#include <atomic.h>
#include <kmalloc.h>

int ida_init(struct ida *ida, unsigned int total)
{
	unsigned int nbits = 0;

	if ((total == 0) || (ida->bitmap != NULL))
		return -EINVAL;

	nbits = roundup(total, BITS_PER_LONG);
	ida->bitmap = kzalloc(nbits / 8);
	if (ida->bitmap == NULL)
		return -ENOMEM;

	ida->next = 0;
	ida->nbits = total;
	spin_lock_init(&ida->lock);
	return 0;
}

int ida_alloc_range(struct ida *ida, unsigned int start, unsigned int end)
{
	int id = 0, ret = -ENOSPC, max = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&ida->lock, flags);

	max = min(ida->nbits, end);
	id = bitmap_next_zero(ida->bitmap, max, start);
	if (id < max) {
		bitmap_set_bit(ida->bitmap, id);
		ret = id;
	}
	spin_unlock_irqrestore(&ida->lock, flags);

	return ret;
}

int ida_alloc(struct ida *ida)
{
	int id = -1;

	id = ida_alloc_range(ida, ida->next, ida->nbits);
	if (id < 0)
		id = ida_alloc_range(ida, 0, ida->next);

	if (id >= 0)
		ida->next = id + 1;

	return id;
}

int ida_set(struct ida *ida, unsigned int id)
{
	unsigned long flags = 0;

	if (id >= ida->nbits)
		return -EINVAL;

	spin_lock_irqsave(&ida->lock, flags);

	if (bitmap_bit_isset(ida->bitmap, id)) {
		spin_unlock_irqrestore(&ida->lock, flags);
		return -EBUSY;
	}

	bitmap_set_bit(ida->bitmap, id);

	spin_unlock_irqrestore(&ida->lock, flags);

	return 0;
}

void ida_free(struct ida *ida, unsigned int id)
{
	unsigned long flags = 0;

	if (id >= ida->nbits)
		return;

	spin_lock_irqsave(&ida->lock, flags);

	bitmap_clear_bit(ida->bitmap, id);

	spin_unlock_irqrestore(&ida->lock, flags);
}

void ida_destroy(struct ida *ida)
{
	kfree(ida->bitmap);
	ida->bitmap = NULL;
	ida->nbits = 0;
}
