# Design decisions

## Purpose of this file

This file documents design decisions of fluesterfix. It’s supposed to
help contributers as well as security researchers: Why does the program
work the way it does?

## The main goals

In this order:

1.  Protect secret confidentiality.
2.  Simple code that humans understand.
3.  Broad compatibility with browsers, down to Lynx.
4.  Temporarily share short secrets, not huge files.

## Consequences

-   It is better to *destroy* a secret than to *potentially leak it*, if
    that helps keeping the code simpler. Code simplicity is crucial and
    mission critical.
-   LLMs *MUST NOT* be required to understand this program. Humans
    *MUST* be able to understand and reason about every line of code.
-   This program is meant as a *temporary* way to transmit secrets. It
    is *not* the primary storage. We assume that every secret can be
    retransmitted easily.
-   Think *hard* before you add new features, even just cosmetic ones.
    Every line of code is a liability. (No, this does not mean to “golf”
    this program.)
-   No mandatory JavaScript, no mandatory CSS.
-   It’s a bug if something doesn’t work properly in Lynx. We hope that
    this policy helps ensuring compatibility with browsers and
    accessibility devices like screen readers.
