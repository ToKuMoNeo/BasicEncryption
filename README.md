Basic Encryption with Tkinter GUI

The user can input plain text, add a custom key to the Secret Key field, and process the information to obtain the Cipher Text. There will also be an option to copy and reset the Cipher Text.

Using XOR Principle Between Plain Text and Secret Key
  Define the Secret Key and determine its length.
  Divide the Plain Text into Blocks, each of which has the same size as the Secret Key. If it does not fit perfectly, add spaces to the end of the Plain Text.
  Perform encryption with the Secret Key using the XOR operator on each Block. XOR is a bitwise operation, so convert characters to integers using the ord() function and convert integers back to characters using the   chr() function.
