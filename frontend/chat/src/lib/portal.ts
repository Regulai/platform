/** Menus, dialogs and popovers render here: inside the island's token scope, outside its layout. */
export function portalContainer(): HTMLElement {
  return document.getElementById("regulai-chat-portal") ?? document.body
}
