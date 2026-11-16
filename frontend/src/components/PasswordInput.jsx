import { useState } from 'react'

/**
 * A password box with its own show/hide eye.
 *
 * The Jinja page wired this with a delegated click handler reading
 * `data-target`, then swapped the icon class by hand. Each input owning its
 * own reveal state is both shorter and impossible to point at the wrong field.
 */
export default function PasswordInput({ id, value, onChange, ...rest }) {
  const [shown, setShown] = useState(false)

  return (
    <div className="pwd-wrap">
      <input
        className="inp"
        type={shown ? 'text' : 'password'}
        id={id}
        maxLength={128}
        value={value}
        onChange={onChange}
        {...rest}
      />
      <button
        type="button"
        className="eye"
        aria-label={shown ? 'Hide password' : 'Show password'}
        onClick={() => setShown((s) => !s)}
      >
        <i className={shown ? 'fas fa-eye-slash' : 'fas fa-eye'} />
      </button>
    </div>
  )
}
