import React from 'react'
import  { useState, useEffect, useContext } from 'react';
import './dashProfil.css'
import { avatars } from '../../../assets/assets'
import { ProfileContext } from '../../../context/ProfilContext';
import { useTranslation } from 'react-i18next';


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function DashProfil({profil}) {
    const {isBlockedMe, isBlockingHim} = useContext(ProfileContext)
    const { t } = useTranslation();


    const [progress, setProgress] = useState('0%');
    useEffect(() => {
        setTimeout(() => {
          setProgress(profil.rank_progress);
        }, 500); 
      }, []);

    if (isBlockedMe || isBlockingHim) {
        return (
            <div className='profilInfo'>
            <div className="userInfo">
              <div className='userContainer'>
                <div className="userImage">
                  <img src={`${BACKEND_URL}${profil.avatar}`} alt="User Avatar" />
                </div>
                <div className="userProgress">
                  <div className="progresInfo">
                    <div className="nameRank">
                      <h4>{profil.username}</h4>
                      <h4>{t('Rank')} : {profil.rank}</h4>
                    </div>
                    <div className='BlockedMessage'>
                      {isBlockedMe ? <h3>{t('You got blocked from this user')}</h3> : <h3>{t('You have blocked this user')}</h3>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
    }

     const winPer = Math.floor((profil.games_won / profil.games_played) * 100);
    const lossPer = 100 - winPer ;
  return (
    <div className='profilInfo'>
    <div className="userInfo">
      <div className='userContainer'>
        <div className="userImage">
          <img src={`${BACKEND_URL}${profil.avatar}`} alt="User Avatar" />
        </div>
        <div className="userProgress">
          <div className="progresInfo">
            <div className="nameRank">
              <h4>{profil.username}</h4>
              <h4>{t('Rank')} : {profil.rank}</h4>
            </div>
            <div className="userXp box">
              <p>{t('User XP')}</p>
              <p>{profil.xp}xp</p>
            </div>
            <div className="totalGames box">
              <p>{t('Total Games')}</p>
              <p>{profil.games_played}</p>
            </div>
            <div className="win box">
              <p>{t('Win')}</p>
              <p>{winPer}%</p>
            </div>
            <div className="Loss box">
              <p>{t('Loss')}</p>
              <p>{lossPer}%</p>
            </div>
          </div>
          <div className="progresBar">
            <div className='emptyBar'>
              <p>{profil.rank_progress}%</p>
              <div className='filledBar' style={{ width: progress }}></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  )
}

export default DashProfil