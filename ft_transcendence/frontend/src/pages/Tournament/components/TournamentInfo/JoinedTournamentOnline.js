import React from 'react'
import { useState, useEffect, useContext } from 'react'
import useAuth from '../../../../hooks/useAuth'
import useFetch from '../../../../hooks/useFetch'
import Icon from '../../../../assets/Icon/icons'
import { avatars } from '../../../../assets/assets'
import './joinedTournament.css'
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import MainButton from '../../../../components/MainButton/MainButton'
import { UserContext } from '../../../../context/UserContext'
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


function JoinedTournamentOnline({TournamentData}) {
    const { auth }  = useAuth()
    const [joinedOwner, setjoinedOwner] = useState(false);
    const [profilData, setProfilData] = useState([]);
    const {userData, updatetounament} = useContext(UserContext)
    const [progress, setProgress] = useState(0);
    const { t } = useTranslation();



    const date = new Date(TournamentData.tournament_date);
    const {data ,isLoading, error} = useFetch(`${BACKEND_URL}/user/stats/${TournamentData.tournament_creator}`)

    useEffect(() => {
        if (userData.user_id === TournamentData.tournament_creator)
            setjoinedOwner(true)
    },[userData]);

    const formattedDate = date.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: 'short',
    });

    const formattedTime = date.toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
    });

    useEffect(() => {
        if (data) {
          setProfilData(data);
        }
      }, [data]);
      

      useEffect(() => {
        setTimeout(() => {
          setProgress(profilData.rank_progress);
        }, 500); 
      }, []);
  
      const handleStartTournament = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/user/tournament/start/`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${auth.accessToken}`
              },
            });
        
            if (response.ok) {
              const data = await response.json();
              console.log('Tournament started successfully:', data);
           
            } else {
              const errorData = await response.json();
              console.error('Failed to start tournament:', errorData);
              
            }
          } catch (error) {
            console.error('Error starting tournament:', error);
          
          }
      }

      const handleDeleteTournament = async () => {
        try {
          const response = await fetch(`${BACKEND_URL}/user/tournament/`, {
            method: 'DELETE',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${auth.accessToken}`

            },
          });
      
          if (response.ok) {
            const data = await response.json();
            const TournamentResponse = await fetch(`${BACKEND_URL}/user/tournament/`, {
                method: 'GET',
                    headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`
                    }
                });
                
                if (!TournamentResponse.ok) {
                    throw new Error('Network response was not ok');
                }
                const updatedTournamentData = await TournamentResponse.json();
                updatetounament(updatedTournamentData);
            console.log('Tournament deleted successfully:', data);
    
          } else {
            const errorData = await response.json();
            console.error('Failed to delete tournament:', errorData);

          }
        } catch (error) {
          console.error('Error deleting tournament:', error);
   
        }
      };
      
  return (
    <div className="joined-tournament">
       <h1 className='tournament-title'>{TournamentData.tournament_name}ONLINE</h1>
       
       <div className={`tournament-info-container ${TournamentData.tournament_map}`}>
            <div className='tournament-info-item'>
                <Icon name='chump_cup' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{TournamentData.tournament_prize}</p>
                    <span>{t('Total Prize Pool')}</span>
                </div>
            </div>
            <div className='tournament-info-item'>
                <Icon name='calendar' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{`${formattedDate} ${formattedTime}`}</p>
                    <span>{t('Tournament Start')}</span>
                </div>
            </div>
            <div className='tournament-info-item'>
                <Icon name='game_mode' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{t('Game Mode')}</p>
                    <span>1 v 1 li mat khser</span>
                </div>
            </div>
            <div className='tournament-info-item'>
                <Icon name='location' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{t('Map')}</p>
                    <span>{TournamentData.tournament_map}</span>
                </div>
            </div>
            <div className='tournament-subscribers'>
                <div className='tournament-subscribers-avatars'>
                {TournamentData.tournament_participants && TournamentData.tournament_participants.map((player, index) => (
                    <img key={index} className={`image${index + 1}`} src={`${BACKEND_URL}${player.avatar}`} alt={`Player ${index + 1}`} />
               
                ))}
                </div>
                <span className='tournament-subscribers-counter'>
                    {TournamentData.tournament_participants && TournamentData.tournament_participants.length}/4 Joined
                </span>
            </div>
        </div>
        <div className='tournament-desc'>
            <div className='tournament-desc-rules'>
                <div className='tournament-desc-rules-top'>
                    <h1>{t('Attention Pongers')}</h1>
                    <p>simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled</p>
                </div>
                <div className='tournament-desc-rules-top'>
                    <h1>{t('How Does It work ?')}</h1>
                    <p>simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled</p>
                </div>
            </div>
            <div className='tournament-top-player-container'>
                <div className='tournament-top-player'>
                    <div className='tournament-top-player-avatar'>
                        <img src={avatars[0].img}/>
                        <div className='nameRank'>
                            <span>{profilData.username}</span>
                            <span>Rank{t('FRIENDS')} : {profilData.rank}</span>
                        </div>
                    </div>
                    <div className='tournament-top-player-stats'>
                        <div className='ownerWinRate'>
                            <CircularProgressbar
                                value={75}
                                text={`${75}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                            <p>WinRate</p>
                        </div>
                        <div className='ownerWinRate'>

                            <CircularProgressbar
                                value={30}
                                text={`${30}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                            <p>WinRate</p>

                            </div>
                            <div className='ownerWinRate'>

                            <CircularProgressbar
                                value={92}
                                text={`${92}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                            <p>WinRate</p>

                            </div>
                    </div>
                    
                </div>
                
            </div>
            
        </div>
        <div className='JoinedTournomanentButoon'>
            {joinedOwner ? (
                <div className='TournamentTwoButton'> 

                    <div className='disapledButton'
                        style={{
                            display: 'inline-block',
                            pointerEvents: TournamentData.tournament_participants && TournamentData.tournament_participants.length < 4 ? 'none' : 'auto',
                            opacity: TournamentData.tournament_participants && TournamentData.tournament_participants.length < 4 ? 0.5 : 1
                        }}
                    >
                        <MainButton type="submit" functionHandler={handleStartTournament} content="Start"/>
                    </div>
                    <MainButton type="submit"  functionHandler={handleDeleteTournament} content="Cancel"/>
                </div>
            ) : (
                <div className='leaveTournomantButton'>
                    <MainButton type="submit"  content="Leave"/>
                </div>
            )}
        </div>
    </div>
  )
}

export default JoinedTournamentOnline