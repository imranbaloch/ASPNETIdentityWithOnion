using System;
using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Core.DomainModels
{
    public class PaginatedList<T> : List<T>
    {
        public int PageIndex { get; private set; }
        public int PageSize { get; private set; }
        public int TotalCount { get; private set; }
        public int TotalPageCount { get; private set; }

        public bool HasPreviousPage
        {

            get
            {
                return (PageIndex > 1);
            }
        }

        public bool HasNextPage
        {

            get
            {
                return (PageIndex < TotalPageCount);
            }
        }

        public PaginatedList(IEnumerable<T> source, int pageIndex, int pageSize, int totalCount)
        {

            if (source == null)
            {
                throw new ArgumentNullException("source");
            }

            AddRange(source);
            PageIndex = pageIndex;
            PageSize = pageSize;
            TotalCount = totalCount;
            TotalPageCount = (int) Math.Ceiling(totalCount/(double) pageSize);
        }
    }
}