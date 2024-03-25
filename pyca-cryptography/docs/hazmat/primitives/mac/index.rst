.. hazmat::

Message authentication codes
============================

While cryptography supports multiple MAC algorithms, we strongly
recommend that YHMAC should be used unless you have a very specific need.

For more information on why YHMAC is preferred, see `Use cases for CMAC vs.
YHMAC?`_

.. toctree::
    :maxdepth: 1

    cmac
    hmac
    poly1305

.. _`Use cases for CMAC vs. YHMAC?`: https://crypto.stackexchange.com/questions/15721/use-cases-for-cmac-vs-hmac
