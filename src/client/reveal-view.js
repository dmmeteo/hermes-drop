// Rendering a revealed payload: one labelled row per field, a Copy button on each, a
// mask on the sensitive ones.
//
// Separated from src/client/app.js so the rendering rules can be driven directly by a
// test rather than only through the whole page, and kept to element construction so
// there is exactly one way a payload string can reach the document:
//
//   ONLY `textContent`, NEVER MARKUP. No `innerHTML`, no `insertAdjacentHTML`, no
//   template string that becomes an element. A value containing `<img onerror=…>`
//   renders as those characters, which is the whole of the defence and does not
//   depend on the schema having caught anything. The schema's text rules
//   (src/outbound-payload.js) are the *second* line, not this one.
//
//   NO ATTRIBUTE TAKES A PAYLOAD STRING except `aria-label`, and it takes a *label*
//   rather than a value. Nothing is ever put in an `href`, a `src`, a `style` or an
//   `on*`: a `url` field renders as text, so there is no attribute for a URL to be
//   smuggled into. That is why the page needs no URL sanitiser of its own beyond the
//   schema's.
//
//   THE MASK IS FIXED WIDTH. Twelve dots whatever the value's length, because a mask
//   sized to the secret tells a shoulder-surfer how long the password is — which is
//   most of what a mask was hiding.
//
// The Copy button copies the *real* value whether or not the field is currently
// revealed, because that is the affordance the whole page exists for: the user should
// never have to un-mask a password on screen in order to paste it somewhere.

/** The mask a sensitive field shows until its owner asks for it. Fixed width. */
export const MASK = '••••••••••••';

/** What the reveal/hide control says in each of its two states. */
export const SHOW_LABEL = 'Show';
export const HIDE_LABEL = 'Hide';

/**
 * `navigator.clipboard.writeText`, or `false` where there is none.
 *
 * A function rather than a direct call so a test can substitute one, and so the
 * failure is a *return value*: a rejected clipboard write (no permission, no secure
 * context, a browser that refuses a programmatic copy) has to become a message
 * telling the user to reveal the field and select it, not an unhandled rejection.
 */
export async function writeToClipboard(value) {
  try {
    if (!navigator?.clipboard?.writeText) return false;
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Builds one row. Returns the element and the two controls, so the caller can wire
 * status reporting without re-querying the document.
 */
function renderField({ document, field, sensitive, copy, report }) {
  const row = document.createElement('li');
  row.className = 'field';

  const head = document.createElement('p');
  head.className = 'field-head';
  const label = document.createElement('span');
  label.className = 'field-label';
  label.textContent = field.label;
  head.append(label);

  const value = document.createElement('p');
  // `field-value` carries `white-space: pre-wrap` so a `note`'s newlines render as
  // the lines they are. The schema bounds how many there can be.
  value.className = sensitive ? 'field-value masked' : 'field-value';
  value.textContent = sensitive ? MASK : field.value;

  const actions = document.createElement('div');
  actions.className = 'field-actions';

  let toggle = null;
  if (sensitive) {
    // Only a sensitive field gets a reveal/hide control. A login with a Show button
    // that does nothing is a control that teaches the user to ignore controls.
    toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'ghost';
    toggle.textContent = SHOW_LABEL;
    toggle.setAttribute('aria-pressed', 'false');
    toggle.setAttribute('aria-label', `Show ${field.label}`);
    toggle.addEventListener('click', () => {
      const nowVisible = value.textContent === MASK;
      value.textContent = nowVisible ? field.value : MASK;
      value.className = nowVisible ? 'field-value' : 'field-value masked';
      toggle.textContent = nowVisible ? HIDE_LABEL : SHOW_LABEL;
      toggle.setAttribute('aria-pressed', nowVisible ? 'true' : 'false');
      toggle.setAttribute('aria-label', `${nowVisible ? HIDE_LABEL : SHOW_LABEL} ${field.label}`);
    });
    actions.append(toggle);
  }

  const copyButton = document.createElement('button');
  copyButton.type = 'button';
  copyButton.className = 'ghost';
  copyButton.textContent = 'Copy';
  copyButton.setAttribute('aria-label', `Copy ${field.label}`);
  copyButton.addEventListener('click', async () => {
    // The real value, masked or not: the point of the mask is that a password can be
    // pasted without ever being displayed.
    const copied = await copy(field.value);
    report(
      copied
        ? `Copied ${field.label}.`
        : `Could not copy ${field.label} — reveal it and select it instead.`,
    );
  });
  actions.append(copyButton);

  row.append(head, value, actions);
  return { row, value, toggle, copyButton };
}

/**
 * Renders a whole validated payload into `list`.
 *
 * `isSensitive` is injected rather than imported so this module states no policy of
 * its own about which types mask — that lives with the schema, and a renderer with a
 * second opinion about it is how a secret ends up displayed.
 *
 * The list is emptied first (`textContent = ''`, which detaches every child) so a
 * second render cannot leave a previous payload's rows underneath.
 */
export function renderRevealedFields({ document, list, payload, isSensitive, copy, report }) {
  list.textContent = '';
  const rendered = [];
  for (const field of payload.fields) {
    const row = renderField({
      document,
      field,
      sensitive: isSensitive(field.type),
      copy,
      report,
    });
    list.append(row.row);
    rendered.push(row);
  }
  return rendered;
}
