# lethewis-timelock

A time lock on the drand network quicknet, which signs a round every three seconds. A key is
locked until a round in an age file tlock tools open; that round's signature opens it.

No network and no clock: the caller brings the signature and the time.

Licensed under AGPL-3.0-only; the text is in the package. A commercial licence without the AGPL's
obligations is available: <hi@alanwisper.com>.
