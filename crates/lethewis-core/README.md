# lethewis-core

Key derivation, hierarchy, lifecycle and destruction for a device that may be taken from its owner.
Pure logic: no filesystem, no network, no clock, no memory allocator. The one question put to the
system, through `lethewis-dit`, is whether the processor offers data-independent timing.

What is guaranteed, what is not, and which properties are proven:
[the repository](https://github.com/wisper-dev/lethewis).

Licensed under AGPL-3.0-only; the text is in the package. A commercial licence without the AGPL's
obligations is available: <hi@alanwisper.com>.
