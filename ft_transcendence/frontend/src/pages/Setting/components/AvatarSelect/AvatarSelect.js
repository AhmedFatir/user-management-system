import React, { useState } from 'react'
import './AvatarSelect.css'
import { avatars } from '../../../../assets/assets'
import { assets } from '../../../../assets/assets'


const AvatarSelect = (props) => {
    const handleFileChange = (event) => {
        props.setAvatarFile(event.target.files[0])
        props.setActiveAvatar(null)
    };

  return (
    <div className='avatar-select'>
        <img src={props.activeAvatar === null ? avatars[0].img : avatars[props.activeAvatar].img} className='selected-avatar'/>
        {avatars.map((item, index) => <img key={index} src={item.img} className={`avatar-item ${props.activeAvatar === index ? 'active' : ''}`} onClick={() => {
            props.setActiveAvatar(index)
        }}/>)}
        <label>
            <input
                type="file"
                name="avatar"
                id='uploadBtn'
                className='upload-input'
                onChange={handleFileChange}
                accept="image/*"
            />
            <label htmlFor="uploadBtn">
                <img src={assets.addAvatar} alt="Upload Avatar" />
            </label>
        </label>
    </div>
  )
}

export default AvatarSelect
