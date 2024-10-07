import React from 'react'
import Icon from '../../../assets/Icon/icons'
import './achievmentsItem.css'
import { useTranslation } from 'react-i18next';

function AchievmentsItem({achiev}) {
    const { t } = useTranslation();
  return (
    <div className={achiev.unlocked === "false" ? 'AchievmentsItemContainer unlockedAchiev' : 'AchievmentsItemContainer'}>
        <div className='IconContainer'>
            <Icon name={achiev.image} className="AchievmentsIcon"/> 
 
        </div>
        <div className='AchievmentsInfo'>
            <div className='AchievmentsName'>
                <p>{t(achiev.title)}</p>
            </div>
            <div className='AchievmenstDescription'>
                <p style={{color: '#8D93AC'}}>{t(achiev.description)}</p>
            </div>
        </div>
    </div>
  )
}

export default AchievmentsItem