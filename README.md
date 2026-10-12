# reflector v2

**Why v2? Because it needs no paid Burp Suite.** The original [reflector](https://github.com/elkokc/reflector) only works as a Burp *Scanner* check, and the Scanner exists only in Burp Professional. On Burp Community it loads, shows a tab, and then never finds anything. **v2 reads your Proxy traffic itself, so it works on the free Community edition** (and still uses the Scanner on Pro).

## How it works

1. **You browse through Burp as usual.** For every response that passes through the Proxy, v2 takes each request parameter (URL, body, cookie, JSON, XML, multipart, plus `Referer`, `User-Agent`, `Origin`, `X-Forwarded-*`) and looks for its value in the response.
2. **It also finds encoded reflections:** raw, HTML-escaped (`&lt;`, `&#39;`, `&#x27;`) and JSON/JS-escaped (`\"`, `\u003c`) forms count too.
3. **Reflected? The history row turns orange** and gets a comment like `Reflector v2: language`, so you see it right in Proxy history.
4. **Aggressive mode** then re-sends the request in the background with `p@y<"'p@y` in the reflected parameter and reads back which of `<` `"` `'` survive unescaped. **Probes never block your browser**, and the same endpoint+parameter is probed only once.
5. **Check context** mode goes further and works out *where* it lands (HTML, attribute, JS string) and which character breaks out of it.
6. **Everything is listed in the Results tab:** host, URL, parameter, where it reflects, severity (High = dangerous characters survive, Medium = reflected but escaped), allowed characters / context, with a request/response viewer.

On Burp Pro the Scanner check also raises normal "XSS (possible/vulnerable)" issues. Pick the mode with the **Proxy listener** checkbox (on by default on Community, off on Pro).

## Install

Build the jar with `./build.sh` (or take it from the Releases page if one is published), then Burp → Extender → Extensions → Add → Type: Java → select the jar. **Scope only is on by default**: add your target to Target → Scope or untick the option, otherwise nothing is analysed. Aggressive mode sends extra requests, so only use it on targets you are allowed to test.

## What changed from the original

* No paid Burp needed (Proxy listener + Results tab).
* Scope only on by default; thread-safe severity (concurrent scans could swap "possible"/"vulnerable").
* Encoded reflections, JSON numbers/booleans and 2-character values are tested; header reflections added.
* JSON/JS/XML responses and responses without a Content-Type are tested too.
* Probe cache, correct `Content-Length` on probes, no crash on null responses or failed probes.

## Build and test

Needs a JDK; the tests need no Burp.

    ./build.sh test     # offline suite against a fake Burp API + simulated vulnerable app
    ./build.sh          # build/reflectorv2.jar

Based on [elkokc/reflector](https://github.com/elkokc/reflector); original README below.

---
# reflector [<img src="https://github.com/elkokc/reflector/blob/master/screenshot/release-v2.0-blue.svg">](https://github.com/elkokc/reflector/releases/tag/2.1)


# Description
Burp Suite extension is able to find reflected XSS on page in real-time while browsing on web-site and include some features as:
* Highlighting of reflection in the response tab.
* Test which symbols is allowed in this reflection.
* Analyze  of reflection context.
* Content-Type whitelist.
 
 
 # How to use
After plugin install you just need to start work with the tested web-application. Every time when reflection is found, reflector defines severity and generates burp issue.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/reflector_demo1.gif)

Each burp issue includes detailed info about reflected parameter, such as:
* Symbols that allowed in this reflection.
* Highlighting of reflection value in response.
* Reflection context analyze.

# Allowed symbols analyse
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/symbols_analyse.png)
When the reflection is found and option "Aggressive mode" is activated, the reflector will check which of special-symbols are displayed on this page from vulnerable parameters. For this action, reflector compose additional requests for each reflected parameter. In example, while we were working with elkokc.ml website reflector are generated issue with a detailed information about reflection. There are 3 reflection for "search" parameter and each of them pass special symbols. Because of the possibility of displaying special characters issue severity is marked as high. Every time when reflection is found reflector define severity and generate burp issue.

# Context analyse
In the "Check context" mode  reflector it's not only show special characters that are reflected to the page, but also figure out a character that allows to break the syntax in the page code. In example you may see server response by reflector extension. Parameter "search" was send with a payload  - p@y<"'p@y. As a result, it was reflected a few times in a different contexts. 
* reflection with next characters - ',", <  and the double quote  allow to exit from this context and write HTML code.
* reflection with next characters - ", <  and the bracket allow to inject HTML-tags. 
* reflection with next characters -  ',", < and the single quote allow to exit from js variable context and write malicious code.

![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/aggressivemode_context.png)

In the issue information it's marked as: 
* Context char - character that allows to breake the syntax.
* Other chars - other chars that are reflected without context.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/aggressivemode_context_burp.png)

# Reflection navigation
Navigation by arrow buttons in the response tab.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/navigation.gif)

# Settings
* Scope only - allow reflector to work only with a scope added websites.
* Agressive mode - reflector generates additional request with a test payload .
* Check context - activate check context mode.

Moreover you can manage content-types whitelist with which  reflector plugin should work. But if you will use another types except text/html,  this can lead to slowdowns in work.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/settings.png)

# How to compile
Compiled by jdk 1.7

Example:

* javac.exe -d build src/burp/*.java

* jar.exe cf plugin.jar -C build burp

# Authors
* Shvetsov Alexandr (GitHub: ![shvetsovalex](https://github.com/shvetsovalex))
* Dimitrenko Egor (GitHub: ![elkokc](https://github.com/elkokc))
