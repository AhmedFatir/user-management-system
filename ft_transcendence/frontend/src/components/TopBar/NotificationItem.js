import React from 'react'
import { useState, useEffect } from 'react';
import './notificationItem.css'
import useFetch from '../../hooks/useFetch'
import NotificationPopup from './NotificationPopup';
import { formatDistanceToNow, parseISO } from 'date-fns';
import { useTranslation } from 'react-i18next'



const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function formatTimeAgo(dateString) {

  const date = parseISO(dateString);
  const timeAgo = formatDistanceToNow(date, { addSuffix: true });

  return timeAgo
}



function NotificationItem({notif, onClick }) {
  const { t } = useTranslation();

  return (
      <div className="notifCard" onClick={() => onClick(notif)}>
        <div className="notifImage">
            <img src={`${BACKEND_URL}${notif.sender_avatar}`} alt="profil_pic" />
        </div>
        <div className="notifInfo">
            <p>{notif.sender_username}<span>{t(notif.message)}</span></p>
            <span className='notifTime'>{formatTimeAgo(notif.timestamp)}</span>
        </div>
      </div>

  )
}

export default NotificationItem