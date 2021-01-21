﻿namespace CloudFoundry.Doppler.Client
{
    using System;
    using DropsondeProtocol;

    /// <summary>
    /// An EventArgs class for message events.
    /// </summary>
    public class MessageEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the message that was received from Doppler.
        /// </summary>
        /// <value>
        /// The message that was received from Doppler.
        /// </value>
        public Envelope LogMessage
        {
            get;
            internal set;
        }
    }
}