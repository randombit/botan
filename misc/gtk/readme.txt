
This is an example of how to use Botan in a GUI. You need at least
Botan 1.4.x.

You'll also need GTK+ 2.x (tested with GTK+ 2.2 and 2.6). Keep in mind
that I was learning GTK as I was writing this code, so it is not
exactly the best GTK code you're likely to see.

dsa.cpp is the main GTK+ driver. It has some comments at the top which point
out major areas of interest.

gtk_ui.* implement a User_Interface object that opens up a GTK+ dialog box that
asks the user for their passphrase. It works pretty well, the only major
deficiency is a fixed upper limit on the size of the passphrase (currently 64).
You may want to use this in your own code, assuming you use GTK. If not, it
should at least provide an outline for writing a version for your favorite
windowing system.

To build, you'll need to have GNU make, or be willing to compile it by hand.
