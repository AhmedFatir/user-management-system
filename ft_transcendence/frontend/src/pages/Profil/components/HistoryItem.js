import React from 'react'
import { useState, useEffect } from 'react';
import useFetch from '../../../hooks/useFetch';
import './historyItem.css'
import { useTranslation } from 'react-i18next';
import { formatDistanceToNow, parseISO } from 'date-fns';


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function formatTimeAgo(dateString) {
  const date = parseISO(dateString);
  return formatDistanceToNow(date, { addSuffix: true });
}

function HistoryItem( {history} ) {
  const { t } = useTranslation();


    
    let player = history.winner_user
    if (history.is_winner)
        player = history.loser_user

     const winPer = Math.floor((30 / 100) * 100);
  return (
    <div className={history.is_winner ? "card won" : "card loss"}>
      <div className="playerImage">
        <img src={`${BACKEND_URL}${player.avatar}`} alt="Player Avatar" />
      </div>
      <div className="playerInfo">
        <div className="nameRank">
          <h4>{player.username}</h4>
          <p style={{ color: '#737373', paddingTop: '5px' }}>
            {t('Rank')} : {player.rank}
          </p>
        </div>
        <div className='playerInfoBox'>
          <div className="totalGames box">
            <p>{t('Total Games')}</p>
            <p className='parg' style={{ color: '#8D93AC' }}>{player.games_played}</p>
          </div>
          <div className="win box">
            <p>{t('Win')}</p>
            <p className='parg' style={{ color: '#8D93AC' }}>{winPer}%</p>
          </div>
          <div className={history.is_winner ? "defeat box true" : "defeat box false"}>
            <p>{t('DEFEAT')}</p>
            <p className='parg clr'>{history.winner_score}:{history.loser_score}</p>
          </div>
          <div className="Loss box">
            {/* <p>{t('Played')}</p> */}
            <p className='parg' style={{ color: '#8D93AC' }}>{formatTimeAgo(history.played_at)}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default HistoryItem