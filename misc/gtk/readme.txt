
This is an example of how to use Botan in a GUI. You need at least Botan 1.3.8,
and I would recommend 1.4.2.

You'll also need GTK+ 2.x (I'm using 2.2, but AFAIK not any 2.2-specific
functionality). Keep in mind that I was learning GTK as I was writing this, so
it's not exactly the best GTK code you're likely to see.

dsa.cpp is the main GTK+ driver. It has some comments at the top which point
out major areas of interest.

gtk_ui.* implement a User_Interface object that opens up a GTK+ dialog box that
asks the user for their passphrase. It works pretty well, the only major
deficiency is a fixed upper limit on the size of the passphrase (currently 64).
You may want to use this in your own code, assuming you use GTK. If not, it
should at least provide an outline for writing a version for your favorite
windowing system.

To build, you'll need to have GNU make, or be willing to compile it by hand.
Just go get gmake, enough real stuff needs it anyway.

Jack
