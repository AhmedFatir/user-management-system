import React, { useEffect, useState } from 'react';

const WS_BACKEND_URL = process.env.REACT_APP_WS_BACKEND_URL;



const AchievementsPopup = () => {
  useEffect(() => {
      const socket = new WebSocket(`${WS_BACKEND_URL}/ws/test/`);

      socket.onopen = function(event) {
          console.log('WebSocket connection opened');
      };

      socket.onmessage = function(event) {
          const data = JSON.parse(event.data);
   
      };

      socket.onerror = function(error) {
          console.error('WebSocket error:', error);
      };

      socket.onclose = function(event) {
          console.log('WebSocket connection closed:', event);
      };
      
    }, []);
    
  return (
    <div className='achievements-popup'>
      <div className='achievement'>
        <h3>aa</h3>
        <p>bb</p>
      </div>
    </div>
  );
};

export default AchievementsPopup;
