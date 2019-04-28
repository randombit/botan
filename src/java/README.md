## Experimental Java Interface using Project Panama 
This is an experimental interface using [Java 13 Project Panama](http://openjdk.java.net/projects/panama/)
and it is supported at the moment just on Linux.

The make_botan.sh script uses jextract from the ffi interface since project
panama support well just plain C at this stage.

In order to try this experimental extension you should:
1. Install Jetbrains idea in /opt/jetbrains/idea or change botan.properties
1. Install Project Panama JDK Early Build access JVM at https://jdk.java.net/panama/
2. We suppose that your JAVA_HOME is /opt/java, so extract the build at /opt/java
3. Install Botan at /usr/local or modify make_botan.sh to point to your botan path.
4. Run make_botan.sh
5. For build and test ant -f build.xml test
# Gradle support
The gradle support is here, but at the current state Gradle is not supporting
JDK 13 since it is not in general availability.

Enjoy!
- @jphoenix - Giorgio Zoppi


