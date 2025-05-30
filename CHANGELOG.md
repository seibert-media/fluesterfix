# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 3.0.0 - 2025-05-06

### Changed

-   New default corporate design.

### Fixed

-   Compatibility with Flask 3.0.
-   Fixed issues with UTF-8 in filenames.

## 2.2.0 - 2022-09-08

### Added

-   A more verbose warning about secrets that have already been
    retrieved.
-   File uploads as an alternative to the plain text field.

## 2.1.1 - 2022-03-15

### Fixed

-   Don't use overly broad `except:`, which is a code smell.

## 2.1.0 - 2022-02-11

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
