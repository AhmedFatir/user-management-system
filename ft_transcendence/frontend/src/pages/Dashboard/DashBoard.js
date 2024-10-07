import React, { useEffect, useState, useContext } from 'react'
import { useTranslation } from 'react-i18next'
import LanguageSelector from '../../components/TopBar/LanguageSelector'
import './dashboard.css'
import DashProfil from './components/DashProfil'
import MatchHistory from './components/MatchHistory'
import Achievments from './components/Achievments'
import Friends from './components/Friends'
import useFetch from '../../hooks/useFetch'
import LineChart from './components/LineChart'
import { UserContext } from '../../context/UserContext'
import FriendsMedia from './components/FriendsMedia'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const DashBoard = () => {
  const [profilData, setProfilData] = useState([]);
  const { t } = useTranslation();

  const {userData} = useContext(UserContext)
 

  return (
    <div className='dashboard-contianer'>
       <div className='page-title'>
           <h1>{t('Welcome back')} {userData.username}</h1>
       </div>
       <div className="dashboard">
          <div className="profilHistoryAcgievmeants-container">
              <div className="profil-container">
                <DashProfil profilData={userData}/>
              </div>
              <div className="historyAchievments-container">
                <div className='friends-container-media'>
                    <FriendsMedia />
                </div>
                <div className="history-container">
                <MatchHistory profilData={profilData} /> 
                </div>
                <div className="achievments-container">
                <Achievments />
                </div>
              </div>
              <div className='lineChart-container'>
                <h2>{t('Graph Growth')}</h2>
                <LineChart />
              </div>
          </div>
          <div className="friends-container">
           
            <Friends /> 
          </div>
       </div>
    </div>
  )
}

export default DashBoard