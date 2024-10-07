import React from 'react'
import  { useState, useEffect } from 'react';
import './dashProfil.css'
import { useTranslation } from 'react-i18next';
import { avatars } from '../../../assets/assets'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function DashProfil({profilData}) {
  const [progress, setProgress] = useState('0%');
  const { t, i18n } = useTranslation();

  const isArabic = i18n.language === 'ar';

  useEffect(() => {
      setTimeout(() => {
        setProgress(profilData.rank_progress);
      }, 500); 
    }, []);

     const winPer = Math.floor((profilData.games_won / profilData.games_played) * 100);
    // const winPer = Math.floor((30 / 100) * 100);
    const lossPer = 100 - winPer ;
// ALSO
    return (
        <div className={`profilInfo ${isArabic ? 'rtl' : 'ltr'}`}>
            <div className="userInfo">
                <div className='userContainer'>
                    <div className="userImage" >
                        <img src={`${BACKEND_URL}${profilData.avatar}`} alt={`${profilData.username} avatar`} />
                    </div>
                    <div className="userProgress">
                        <div className="progresInfo">
                            <div className="nameRank">
                                <h4>{profilData.username}</h4>
                                <h4>{t('Rank')} : {t(profilData.rank)}</h4>
                            </div>
                            <div className="userXp box">
                                <p>{t('User XP')}</p>
                                <p>{profilData.xp}xp</p>
                            </div>
                            <div className="totalGames box">
                                <p>{t('Total Games')}</p>
                                <p>{profilData.games_played}</p>
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
                                <p>{profilData.rank_progress}%</p> 
                                <div className='filledBar' style={{ width: progress }}></div>
                            </div>
                        </div>
                </div>
                </div>
            </div>
        </div>
    );
}

export default DashProfil