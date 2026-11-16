/**
 * The card every section on the page sits in.
 *
 * In the Jinja pages this eleven-line block of markup was pasted once per
 * section, per page — four times in settings.html alone, and again in
 * admin.html and users.html with small differences that had already drifted.
 * This is the shape of the win from the migration: one definition, no drift.
 */
export default function Panel({ icon, title, sub, tools, children, footer, ...rest }) {
  return (
    <section className="panel" {...rest}>
      <div className="panel-head">
        <div className="titles">
          <h2>
            {icon && <i className={icon} />} {title}
          </h2>
          {sub && <div className="panel-sub">{sub}</div>}
        </div>
        {tools && <div className="panel-tools">{tools}</div>}
      </div>
      {children}
      {footer}
    </section>
  )
}

/** Body and foot are separate exports so a <form> can wrap both (see DetailsPanel). */
export const PanelBody = ({ children }) => <div className="panel-body">{children}</div>

export const PanelFoot = ({ hint, children }) => (
  <div className="panel-foot">
    <span className="hint" style={{ margin: 0 }}>
      {hint}
    </span>
    <span className="spacer" />
    {children}
  </div>
)

/**
 * The primary action button. `loading` drives the same .loading class the
 * stylesheet already animates, and disables the button so a slow save cannot
 * be double-submitted.
 */
export function Button({ variant, loading, icon, children, ...rest }) {
  const cls = ['btn', variant, loading && 'loading'].filter(Boolean).join(' ')
  return (
    <button className={cls} disabled={loading || rest.disabled} {...rest}>
      <span className="spin" />
      {icon && <i className={icon} />} {children}
    </button>
  )
}
