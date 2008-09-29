/*************************************************
* GTK+ User Interface Source File                *
*************************************************/

#include "gtk_ui.h"

/*************************************************
* GTK+ Callback                                  *
*************************************************/
void GTK_UI::callback(GtkWidget* entry, gpointer passphrase_ptr)
   {
   const gchar *entry_text = gtk_entry_get_text(GTK_ENTRY(entry));
   char* passphrase = (char*)passphrase_ptr;
   strcpy(passphrase, entry_text);
   }

/*************************************************
* Get a passphrase from the user                 *
*************************************************/
std::string GTK_UI::get_passphrase(const std::string& what,
                                   const std::string& source,
                                   UI_Result& result) const
   {
   std::string msg = "A passphrase is needed to access the " + what;
   if(source != "") msg += "\nin " + source;
   return get_passphrase(msg, result);
   }

/*************************************************
* Get a passphrase from the user                 *
*************************************************/
std::string GTK_UI::get_passphrase(const std::string& label_text,
                                   UI_Result& result) const
   {
   const int MAX_PASSPHRASE = 64;

   GtkDialogFlags flags =
      (GtkDialogFlags)(GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_MODAL);

   GtkWidget* dialog = gtk_dialog_new_with_buttons(
      "Enter Passphrase",
      NULL, flags,
      GTK_STOCK_OK, GTK_RESPONSE_OK,
      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
      NULL);

   gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);

   GtkWidget* label = gtk_label_new(label_text.c_str());

   GtkWidget* entry = gtk_entry_new();
   gtk_entry_set_visibility(GTK_ENTRY(entry), 0);
   gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
   gtk_entry_set_max_length(GTK_ENTRY(entry), MAX_PASSPHRASE);

   char passphrase_buf[MAX_PASSPHRASE + 1] = { 0 };

   gtk_signal_connect(GTK_OBJECT(entry), "activate",
                      GTK_SIGNAL_FUNC(callback), passphrase_buf);

   GtkWidget* vbox = gtk_vbox_new(FALSE, 0);
   gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
   gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);

   gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), vbox, TRUE, TRUE, 0);
   gtk_widget_show_all(vbox);

   /* Block until we get something back */
   result = CANCEL_ACTION;
   if(gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK)
      result = OK;

   gtk_widget_destroy(dialog);

   if(result == OK)
      return std::string(passphrase_buf);
   return "";
   }
