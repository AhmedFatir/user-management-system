import React from 'react'
import './SettingInput.css'




const SettingInput = (props) => {
  return (
    <div className='setting-input-container'>
            <span>{props.label}</span>
            <input 
            name={props.name} 
            type={props.type} 
            placeholder={props.placeholder} 
            onChange={props.onChange}
            disabled={props.disabled}
            />
    </div>
  )
}

export default SettingInput