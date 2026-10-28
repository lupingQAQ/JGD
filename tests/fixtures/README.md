# Parser fixtures

`sample.jar` contains five `.class` files extracted from
**Apache Commons Collections 3.2.1** (Apache License 2.0). They are used only
as a parser/reader fixture; no target code is loaded or executed.

`commons-collections-3.2.1.jar` is the full upstream JAR from the same release,
used for trusted dynamic-probe tests only (host sandbox opt-in in tests, never
the default product path).

Source: `https://commons.apache.org/proper/commons-collections/`
License: Apache-2.0
