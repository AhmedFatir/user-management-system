import React from 'react'
import { useEffect, useState, useContext } from 'react'
import './achievments.css'
import AchievmentsData from '../../../assets/AchievmentsData'
import AchievmentsItem from './AchievmentsItem'
import useFetch from '../../../hooks/useFetch'
import { UserContext } from '../../../context/UserContext'
import { useTranslation } from 'react-i18next'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


function Achievments() {
  const [achievements, setAchievements] = useState(AchievmentsData.map(achiev => ({ ...achiev, unlocked: "false" })));
  const {userAchievements} = useContext(UserContext)
  const { t } = useTranslation();


  useEffect(() => {
    if (userAchievements && userAchievements.length) {
      const updatedAchievements = achievements.map(achiev => {
        const isAchieved = userAchievements.some(userAchiev => userAchiev.achievement?.title  === achiev.title);
        return {...achiev, unlocked: isAchieved ? "true" : "false"};
      });
      setAchievements(updatedAchievements);
    }
  }, [userAchievements]);

  return (
    <div className='achievmentsContainer'>
        <div className='achievmentsHeader'>
          <h2>{t('Achievements')}</h2>
        </div>
        <div className='achievmentsCard'>
            {achievements.map((achiev) => (
                <AchievmentsItem key={achiev.id} achiev={achiev}/>
            ))}
        </div>

    </div>
  )
}

export default Achievments