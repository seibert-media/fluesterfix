# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## next

### Added

-   Introduce new environment variables to make it easier to customize
    CSS and logos.

## 2.0.0 - 2021-06-17

### Changed

-   This project now uses the corporate //SEIBERT/MEDIA design (mostly).

### Added

-   Display of textareas uses the webfont "Ubuntu Mono" to avoid
    ambiguities (`l` vs. `1` and similar). This requires serving a
    ~200kB font file.
-   Implemented a user request: We now check whether a requested secret
    exists before offering the form to reveal it.
-   JSON API to create new secrets.

## 1.0.0 - 2020-10-30

-   Initial release.
