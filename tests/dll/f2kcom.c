/*
 * f2kcom - the dll fixture's companion DLL (see dll.c).
 *
 * Built with no C runtime and no entry point: the loader maps the
 * image and resolves its exports, and nothing runs at load time.
 * The functions work without any initialization - the mapping zeroes
 * the counter and carries the string - so the exports are plain
 * functions over the DLL's own data, and a reload after an unload
 * starts the counter over. The ordinals are pinned by f2kcom.def.
 */

int __stdcall f2k_sum(int a, int b)
{
    return a + b;
}

const char *__stdcall f2k_greet(void)
{
    return "hello from f2kcom.dll";
}

int __stdcall f2k_next(void)
{
    static int n;

    return ++n;
}
