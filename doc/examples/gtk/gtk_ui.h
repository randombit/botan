/*************************************************
* GTK+ User Interface Header File                *
*************************************************/

#ifndef BOTAN_EXT_GTK_UI__
#define BOTAN_EXT_GTK_UI__

#include <botan/ui.h>
#include <gtk/gtk.h>

/*************************************************
* GTK+ Passphrase Callback Object                *
*************************************************/
class GTK_UI : public Botan::User_Interface
   {
   public:
      std::string get_passphrase(const std::string&, const std::string&,
                                 UI_Result&) const;

      std::string get_passphrase(const std::string&, UI_Result&) const;

      static void callback(GtkWidget*, gpointer);
   };

#endif
