import React from 'react'
import Style from './MainButton.module.css'

const MainButton = ({type,functionHandler, content}) => {
  return (
    <div className={Style.buttonContainer}>
        <div className={Style.SubmitContainer}>
            <button type={type} onClick={functionHandler} className={Style.SubmitButtonPrimary}>{content}</button>
        </div>
    </div>
  )
}

export default MainButton