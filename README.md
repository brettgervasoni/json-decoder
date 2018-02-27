JSONDecoder
====================

Fork of https://github.com/carstein/burp-extensions, and all credits go to michal.melewski@gmail.com

This fork simply includes the headers in the JSON Decoder tab. I chose to not submit a PR to the original repository as
most people probably only want to see JSON in the JSON Decoder tab.

### JSONDecoder (1.2)
* Included headers in response

### JSONDecoder (1.1)
Quite simply just a JSON pretty printer with some additional features.

* Ability to remove json garbage (like }]);) - it does a bit of guessing, so not always reliable
* Ability to force JSON decoding on atypical content-type (by default decodes only application/json and text/javascript)