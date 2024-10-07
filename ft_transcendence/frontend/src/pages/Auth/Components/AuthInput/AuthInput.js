import React, { useState } from 'react'

const AuthInput = (props) => {
  const [focused, setFocused] = useState(false)
  function handleFocus(e) {
    setFocused(true)
  }  
  return (
          <div className='signup-input'>
            <input
              name={props.name}
              placeholder={props.placeholder}
              type={props.type}
              onChange={props.onChange}
              pattern={props.pattern}
              required
              onBlur={handleFocus}
              focused={focused.toString()}
              />
              <span>{props.errorMessage}</span>
          </div>
      );
}

export default AuthInput