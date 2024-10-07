import React from 'react'
import './firstThreeItem.css'
import Icon from '../../../assets/Icon/icons'
import { avatarsUnkown } from '../../../assets/assets'
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


function FirstThreeItem({player, iconName}) {
  const unknownAvatar = avatarsUnkown.img;
  const { t } = useTranslation();


  return (
    <div className='firstThree-Container'>
        <div className='player-Image'>
            <img src={ player.avatar ? `${BACKEND_URL}${player.avatar}` : unknownAvatar}/>
        </div>
        <div className='playerNameRanke'>
            <h3>{player.username}</h3>
            <p className='rankParag'>{t('Rank')} : {player.rank}</p>
        </div>
        <div className='rankIcon'>
            <Icon name={iconName} className="goldIcon" />
        </div>
    </div>
  )
}

export default FirstThreeItem