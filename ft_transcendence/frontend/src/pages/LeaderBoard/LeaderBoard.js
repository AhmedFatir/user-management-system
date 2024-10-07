import './leaderBoard.css'
import FirstThreeItem from './components/FirstThreeItem'
import LeaderBoardData from '../../assets/LeaderBoardData'
import RestItem from './components/RestItem'
import React, { useEffect, useState } from 'react';
import Lottie from 'lottie-react';
import { useTranslation } from 'react-i18next';
import sadFace from '../../assets/sadFace.json'
import useAuth from '../../hooks/useAuth'
import EmptyRestItem from './components/EmptyRestItem';
import loadingAnimation from '../../components/OauthTwo/loading-animation.json'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

// const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const LeaderBoard = () => {
  const [leaderboardData, setLeaderboardData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const {auth} = useAuth()
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true); 

  const defaultsecond = {user_id: 2, username: 'Uknown Player', rank: 'None'};
  const defaultthird = {user_id: 3, username: 'Uknown Player', rank: 'None'};


  useEffect(() => {
    const fetchLeaderboardData = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/user/leaderboard?page=${page}&limit=20`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${auth.accessToken}`,
          },
        });
  
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
  
        const data = await response.json();
        setLeaderboardData((prevData) => [...prevData, ...data.results]);
        setHasMore(data.results.length > 0); 
     
      } catch (error) {
        setError('Failed to fetch leaderboard data');
      } finally {
        setIsLoading(false);
      }
    };
  
    fetchLeaderboardData();
  }, [page]);


  useEffect(() => {
    const handleScroll = () => {
      if (
        window.innerHeight + window.scrollY >= document.body.offsetHeight - 500 && hasMore
      ) {
        setPage((prevPage) => prevPage + 1);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [hasMore]);

  if (isLoading) return (
    <div className='oauth-loading'>
        <Lottie animationData={loadingAnimation} style={{ width: 400, height: 400 }} />; 
      </div>
    );
  if (error) return <div>Error: {error}</div>;

  const [first, second, third, ...rest] = leaderboardData || [];

  const secondPlayer = second ? second : defaultsecond;
  const thirdPlayer = third ? third : defaultthird;


  return (
    <div className='leaderBoard-Container'>
      <div className='page-title'>
        <h1>{t('LeaderBoard')}</h1>
      </div>
      <div className='leaderBoard-List-Container'>
        <div className='leaderBoard-List'>
            <div className='leaderBoard-FirstThree'>
                {first && <FirstThreeItem key={first.user_id} player={first} iconName="gold"/>}
                {secondPlayer && <FirstThreeItem key={secondPlayer.user_id} player={secondPlayer} iconName="silver"/>}
                {thirdPlayer && <FirstThreeItem key={thirdPlayer.user_id} player={thirdPlayer} iconName="copper"/>}
            </div>
            <div className='leaderBoard-RestList'>
                <div className='restList-Header'>
                      <p>{t('player')}</p>
                      <p>{t('Matchs Played')}</p>
                      <p>{t('Win')}</p>
                      <p>{t('Loss')}</p>
                      <p>{t('Rank')}</p>
                </div>
                <div className='restList-Players'>
                {rest.length > 0 ? (
                      rest.map((players, index) => (
                        <RestItem key={index} players={players} index={index + 4}/>
                      ))
                    ) : (
                      <div className='sadFaceAnimationGame'>
                        <div className='sadeFaceGame'><Lottie  animationData={sadFace} /> </div>
                        <h3>{t('No more players')}</h3>
                       </div>
                    )}
                </div>
            </div>
        </div>
      </div>
    </div>
  )
}

export default LeaderBoard